package store

import (
	"context"
	"embed"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is a handle to the PostgreSQL database.
type Store struct {
	Pool *pgxpool.Pool
}

// Options are the resolved connection settings, normally read from the
// environment to match db/init.py.
type Options struct {
	Host             string
	Port             int
	Database         string
	User             string
	Password         string
	ConnectTimeout   int
	StatementTimeout int
}

// OptionsFromEnv mirrors the PG* variables consumed by db/init.py.
func OptionsFromEnv() Options {
	port, _ := strconv.Atoi(getenv("PGPORT", "5432"))
	timeout, _ := strconv.Atoi(getenv("PGCONNECT_TIMEOUT", "3"))
	stmtTimeout, _ := strconv.Atoi(getenv("PGSTATEMENT_TIMEOUT_MS", "10000"))
	return Options{
		Host:             getenv("PGHOST", "localhost"),
		Port:             port,
		Database:         getenv("PGDATABASE", "network_logs"),
		User:             getenv("PGUSER", "monitor"),
		Password:         getenv("PGPASSWORD", "monitor"),
		ConnectTimeout:   timeout,
		StatementTimeout: stmtTimeout,
	}
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// DSN builds a libpq-style connection string.
func (o Options) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s connect_timeout=%d options='-c search_path=public -c statement_timeout=%d'",
		o.Host, o.Port, o.Database, o.User, o.Password, o.ConnectTimeout, o.StatementTimeout,
	)
}

// Open connects and applies the embedded schema.
func Open(ctx context.Context, opts Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(opts.DSN())
	if err != nil {
		return nil, fmt.Errorf("store: parse config: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	s := &Store{Pool: pool}
	if err := s.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// OpenWithRetry bounds the startup backoff so a slow database does not abort
// the process immediately. Mirrors get_connection_retry(attempts=10).
func OpenWithRetry(ctx context.Context, opts Options, attempts int) (*Store, error) {
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s, err := Open(ctx, opts)
		if err == nil {
			return s, nil
		}
		lastErr = err
		wait := time.Duration(attempt+1) * time.Second
		if wait > 5*time.Second {
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, fmt.Errorf("store: unreachable after %d attempts: %w", attempts, lastErr)
}

// Close releases the pool.
func (s *Store) Close() { s.Pool.Close() }

// Migrate applies the embedded, idempotent migration files in lexical order.
// The frozen schema matches docker/postgres/init.sql.
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("store: read migrations: %w", err)
	}
	// Serialize concurrent migrators (ingest and detector start together).
	if _, err := s.Pool.Exec(ctx, "SELECT pg_advisory_lock(81726391)"); err != nil {
		return fmt.Errorf("store: acquire migration lock: %w", err)
	}
	defer s.Pool.Exec(ctx, "SELECT pg_advisory_unlock(81726391)")

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("store: read %s: %w", entry.Name(), err)
		}
		if _, err := s.Pool.Exec(ctx, string(raw)); err != nil {
			return fmt.Errorf("store: apply %s: %w", entry.Name(), err)
		}
	}
	return nil
}
