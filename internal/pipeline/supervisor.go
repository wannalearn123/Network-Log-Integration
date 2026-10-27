package pipeline

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"sync"

	"siskamlan/internal/config"
	"siskamlan/internal/notify"
	"siskamlan/internal/rules"
	"siskamlan/internal/store"
)

// Config collects the runtime settings for the supervised pipeline.
type Config struct {
	Store     *store.Store
	Rules     *config.File[rules.RulesFile]
	SyslogDir string
	StateFile string
	Notifier  *notify.Notifier
	// OnHits receives detections for the dashboard, if set.
	OnHits func([]rules.Hit)
	// OnIngest receives ingest progress, if set.
	OnIngest func(inserted, total, dropped int)
	// LineBuffer bounds the tailer→ingester channel.
	LineBuffer int
}

// Supervisor runs the tailer, ingester and detector in one process.
type Supervisor struct {
	cfg      Config
	lines    chan string
	ingester *Ingester
	detector *Detector
}

// New prepares the supervised components.
func New(cfg Config) *Supervisor {
	buf := cfg.LineBuffer
	if buf <= 0 {
		buf = 10000
	}
	return &Supervisor{
		cfg:   cfg,
		lines: make(chan string, buf),
		ingester: &Ingester{
			Store:   cfg.Store,
			OnBatch: cfg.OnIngest,
		},
		detector: &Detector{
			Store:                cfg.Store,
			Rules:                cfg.Rules,
			LogRetentionDays:     envInt("LOG_RETENTION_DAYS", 7),
			AnomalyRetentionDays: envInt("ANOMALY_RETENTION_DAYS", 30),
			Notify: func(severity, description string, id int) {
				if cfg.Notifier != nil {
					cfg.Notifier.Send(severity, description, id)
				}
			},
			OnHits: cfg.OnHits,
		},
	}
}

// Run starts every worker and blocks until ctx is cancelled or a worker fails.
func (s *Supervisor) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tailer := &Tailer{
		Dir:       s.cfg.SyslogDir,
		StateFile: s.cfg.StateFile,
		OnError:   func(err error) { log.Printf("tailer: %v", err) },
	}

	var wg sync.WaitGroup
	errs := make(chan error, 3)

	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("%s: %v", name, err)
				select {
				case errs <- err:
				default:
				}
				cancel()
			}
		}()
	}

	run("tailer", func() error { return tailer.Run(ctx, s.lines) })
	run("ingest", func() error { return s.ingester.Run(ctx, s.lines) })
	run("detector", func() error { return s.detector.Run(ctx) })

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		// Wait for workers to flush and close cleanly.
		<-done
		select {
		case err := <-errs:
			return err
		default:
			return nil
		}
	case <-done:
		select {
		case err := <-errs:
			return err
		default:
			return nil
		}
	}
}

// Stats exposes live counters for the dashboard.
func (s *Supervisor) Stats() (total, dropped int) {
	return s.ingester.Total(), s.ingester.Dropped()
}

func envInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return fallback
	}
	return v
}
