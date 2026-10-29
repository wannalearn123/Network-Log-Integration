// Command siskamlan is the LAN security monitor: a syslog parser, an ingest
// pipeline, a dynamic rules engine and a terminal dashboard.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"siskamlan/internal/config"
	"siskamlan/internal/notify"
	"siskamlan/internal/parser"
	"siskamlan/internal/pipeline"
	"siskamlan/internal/rules"
	"siskamlan/internal/store"
	"siskamlan/internal/telegramauth"
	"siskamlan/internal/telegrambot"
	"siskamlan/internal/tui"
)

const usage = `siskamlan — LAN security monitoring

Usage:
  siskamlan <command>

Commands:
  run     run the ingest + detection pipeline without a dashboard
  tui     run the terminal dashboard only
  all     run the pipeline and the dashboard together (default)

Environment: PG* variables configure PostgreSQL, mirroring .env.
`

// projectRoot is resolved from the working directory, overridable for tests.
var projectRoot string

func init() {
	if root := os.Getenv("SISKAMLAN_ROOT"); root != "" {
		projectRoot = root
	} else {
		wd, err := os.Getwd()
		if err != nil {
			wd = "."
		}
		projectRoot = config.LoadDotEnv(filepath.Join(wd, ".env"))
	}
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("[siskamlan] ")

	cmd := "all"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "run":
		err = runPipeline(ctx)
	case "tui":
		err = runTUI(ctx)
	case "all":
		err = runAll(ctx)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "siskamlan: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}

	if err != nil && ctx.Err() == nil {
		log.Fatalf("fatal: %v", err)
	}
}

// buildRuntime assembles the shared runtime: store, rules, parser config and
// supervisor.
// configs holds the loaded, hot-reloadable configuration.
type configs struct {
	paths   config.Paths
	rules   *config.File[rules.RulesFile]
	parsers *pipeline.ParserProvider
}

// loadConfigs seeds and loads both YAML files under root. It touches no
// network resource, so it can be tested without PostgreSQL.
func loadConfigs(root string) (*configs, error) {
	paths := config.DefaultPaths(root)

	rulesFile := config.NewFile[rules.RulesFile](paths.Rules)
	rulesFile.Decode = rules.Decode
	rulesFile.Validate = rules.Validate
	if err := config.LoadOrSeed(rulesFile, rules.DefaultRulesFile(), rules.Encode); err != nil {
		return nil, fmt.Errorf("rules config: %w", err)
	}

	parsersFile := config.NewFile[parser.Config](paths.Parsers)
	parsersFile.Decode = parser.DecodeConfig
	parsersFile.Validate = parser.ValidateConfig
	// Seed with the commented template verbatim, not the re-encoded form.
	if err := seedIfMissing(paths.Parsers, []byte(parser.TemplateYAML)); err != nil {
		return nil, fmt.Errorf("parser config: %w", err)
	}
	if err := parsersFile.Load(); err != nil {
		return nil, fmt.Errorf("parser config: %w", err)
	}

	if rf, _ := rulesFile.Current(); len(rf.Rules) > 0 {
		log.Printf("rules: %d loaded from %s", len(rf.Rules), paths.Rules)
	}
	if pc, _ := parsersFile.Current(); true {
		log.Printf("parsers: %d device profiles from %s", len(pc.Devices), paths.Parsers)
	}

	return &configs{
		paths:   paths,
		rules:   rulesFile,
		parsers: pipeline.NewParserProvider(parsersFile),
	}, nil
}

func buildRuntime(ctx context.Context) (*runtime, error) {
	cfgs, err := loadConfigs(projectRoot)
	if err != nil {
		return nil, err
	}

	s, err := store.OpenWithRetry(ctx, store.OptionsFromEnv(), 10)
	if err != nil {
		return nil, err
	}

	auth := telegramauth.Open(filepath.Join(projectRoot, "data", "telegram_auth.json"))

	sup := pipeline.New(pipeline.Config{
		Store:     s,
		Rules:     cfgs.rules,
		Parsers:   cfgs.parsers,
		SyslogDir: filepath.Join(projectRoot, "data", "syslog"),
		StateFile: filepath.Join(projectRoot, "data", ".pipeline", "offsets.json"),
		Notifier:  notify.New(auth.AuthorizedIDs),
	})
	return &runtime{store: s, supervisor: sup, paths: cfgs.paths, auth: auth}, nil
}

// runtime bundles the long-lived components built for a run.
type runtime struct {
	store      *store.Store
	supervisor *pipeline.Supervisor
	paths      config.Paths
	auth       *telegramauth.Store
}

// startBot runs the Telegram command loop until ctx ends. It does nothing
// unless NOTIFY_TELEGRAM is on and a token is set, so an unconfigured install
// behaves exactly as before.
func (r *runtime) startBot(ctx context.Context) {
	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	if token == "" || !notify.New(nil).Enabled() {
		return
	}
	bot, err := telegrambot.New(telegrambot.Options{
		Token:   token,
		APIBase: os.Getenv("TELEGRAM_API_BASE"),
		Auth:    r.auth,
		Status:  r.statusSnapshot,
	})
	if err != nil {
		log.Printf("telegram: bot disabled: %v", err)
		return
	}
	go func() {
		if err := bot.Run(ctx); err != nil {
			log.Printf("telegram: bot stopped: %v", err)
		}
	}()
}

// statusSnapshot gathers what /status reports. Each probe has its own short
// timeout so a sick database cannot hang the reply.
func (r *runtime) statusSnapshot(ctx context.Context) telegrambot.Status {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	st := telegrambot.Status{PipelineRunning: r.supervisor != nil}
	last, err := r.store.LastLogTime(cctx)
	if err != nil {
		st.DBError = err.Error()
		return st
	}
	st.DBReachable = true
	st.LastIngest = last
	if h, d, err := r.store.AnomalyCounts(cctx); err == nil {
		st.Anomalies1h, st.Anomalies24h = h, d
	}
	return st
}

// seedIfMissing writes template when path does not exist yet, preserving the
// human-readable comments a YAML encoder would drop.
func seedIfMissing(path string, template []byte) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return config.WriteAtomic(path, template)
}

func runPipeline(ctx context.Context) error {
	rt, err := buildRuntime(ctx)
	if err != nil {
		return err
	}
	defer rt.store.Close()
	rt.startBot(ctx)

	log.Printf("pipeline starting — tailing %s", filepath.Join(projectRoot, "data", "syslog"))
	return rt.supervisor.Run(ctx)
}

func runTUI(ctx context.Context) error {
	redirectLogs()
	rt, err := buildRuntime(ctx)
	if err != nil {
		return err
	}
	defer rt.store.Close()
	return rt.runDashboard(ctx, false)
}

func runAll(ctx context.Context) error {
	redirectLogs()
	rt, err := buildRuntime(ctx)
	if err != nil {
		return err
	}
	defer rt.store.Close()
	rt.startBot(ctx)
	return rt.runDashboard(ctx, true)
}

// runDashboard runs the pipeline (when withPipeline) and the dashboard in one
// process. Closing the dashboard cancels the pipeline.
func (r *runtime) runDashboard(ctx context.Context, withPipeline bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if withPipeline {
		done := make(chan error, 1)
		go func() {
			done <- r.supervisor.Run(ctx)
		}()
		defer func() {
			cancel()
			<-done
		}()
	}

	model := tui.New(tui.Options{
		Store:       r.store,
		RulesPath:   r.paths.Rules,
		ParsersPath: r.paths.Parsers,
		ExportDir:   filepath.Join(projectRoot, "exports"),
		Auth:        r.auth,
	})
	program := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		return err
	}
	return nil
}

// redirectLogs sends the standard logger to logs/orchestrator.log so the
// dashboard stays readable.
func redirectLogs() {
	dir := filepath.Join(projectRoot, "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "orchestrator.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(f)
}
