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
	"syscall"

	"siskamlan/internal/config"
	"siskamlan/internal/notify"
	"siskamlan/internal/parser"
	"siskamlan/internal/pipeline"
	"siskamlan/internal/rules"
	"siskamlan/internal/store"
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
func buildRuntime(ctx context.Context) (*runtime, error) {
	paths := config.DefaultPaths(projectRoot)

	rulesFile := config.NewFile[rules.RulesFile](paths.Rules)
	rulesFile.Decode = rules.Decode
	rulesFile.Validate = rules.Validate
	if err := config.LoadOrSeed(rulesFile, rules.DefaultRulesFile(), rules.Encode); err != nil {
		return nil, fmt.Errorf("rules config: %w", err)
	}
	if rf, _ := rulesFile.Current(); len(rf.Rules) > 0 {
		log.Printf("rules: %d loaded from %s", len(rf.Rules), paths.Rules)
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
	if pc, _ := parsersFile.Current(); true {
		log.Printf("parsers: %d device profiles from %s", len(pc.Devices), paths.Parsers)
	}
	provider := pipeline.NewParserProvider(parsersFile)

	s, err := store.OpenWithRetry(ctx, store.OptionsFromEnv(), 10)
	if err != nil {
		return nil, err
	}

	sup := pipeline.New(pipeline.Config{
		Store:     s,
		Rules:     rulesFile,
		Parsers:   provider,
		SyslogDir: filepath.Join(projectRoot, "data", "syslog"),
		StateFile: filepath.Join(projectRoot, "data", ".pipeline", "offsets.json"),
		Notifier:  notify.New(),
	})
	return &runtime{store: s, supervisor: sup}, nil
}

// runtime bundles the long-lived components built for a run.
type runtime struct {
	store      *store.Store
	supervisor *pipeline.Supervisor

	stopTUI context.CancelFunc
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

	log.Printf("pipeline starting — tailing %s", filepath.Join(projectRoot, "data", "syslog"))
	return rt.supervisor.Run(ctx)
}

func runTUI(ctx context.Context) error {
	log.Print("tui: not implemented yet")
	return nil
}

func runAll(ctx context.Context) error {
	// The dashboard is added in a later phase; for now run the pipeline.
	return runPipeline(ctx)
}
