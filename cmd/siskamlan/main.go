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

// build assembles the shared runtime: store, rules config and supervisor.
func build(ctx context.Context) (*store.Store, *pipeline.Supervisor, error) {
	paths := config.DefaultPaths(projectRoot)

	rulesFile := config.NewFile[rules.RulesFile](paths.Rules)
	rulesFile.Decode = rules.Decode
	rulesFile.Validate = rules.Validate
	if err := config.LoadOrSeed(rulesFile, rules.DefaultRulesFile(), rules.Encode); err != nil {
		return nil, nil, fmt.Errorf("rules config: %w", err)
	}
	if rf, _ := rulesFile.Current(); len(rf.Rules) > 0 {
		log.Printf("rules: %d loaded from %s", len(rf.Rules), paths.Rules)
	}

	s, err := store.OpenWithRetry(ctx, store.OptionsFromEnv(), 10)
	if err != nil {
		return nil, nil, err
	}

	sup := pipeline.New(pipeline.Config{
		Store:     s,
		Rules:     rulesFile,
		SyslogDir: filepath.Join(projectRoot, "data", "syslog"),
		StateFile: filepath.Join(projectRoot, "data", ".pipeline", "offsets.json"),
		Notifier:  notify.New(),
	})
	return s, sup, nil
}

func runPipeline(ctx context.Context) error {
	s, sup, err := build(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	log.Printf("pipeline starting — tailing %s", filepath.Join(projectRoot, "data", "syslog"))
	return sup.Run(ctx)
}

func runTUI(ctx context.Context) error {
	log.Print("tui: not implemented yet")
	return nil
}

func runAll(ctx context.Context) error {
	// The dashboard is added in a later phase; for now run the pipeline.
	return runPipeline(ctx)
}
