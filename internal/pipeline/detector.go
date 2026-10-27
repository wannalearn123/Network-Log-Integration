package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
	"siskamlan/internal/rules"
	"siskamlan/internal/store"
)

// Detector defaults, matching the original 15s cadence over a 30s window.
const (
	WindowInterval  = 15 * time.Second
	WindowSize      = 30
	InsertCooldown  = 300 // seconds before the same (type, entity) re-inserts
	FloodCooldown   = 60  // flood-type detections churn faster
	RetentionPeriod = 1 * time.Hour
)

// detectorStore is the subset of the database the detector needs. It is an
// interface so detection logic can be tested without PostgreSQL.
type detectorStore interface {
	QueryWindow(ctx context.Context, windowSeconds int) ([]*store.LogEntry, error)
	InsertAnomaly(ctx context.Context, a store.Anomaly, windowSeconds int) (int, error)
	BumpAnomaly(ctx context.Context, anomalyID, repeatCount int) error
	GetCooldown(ctx context.Context, signature string) (*store.Cooldown, error)
	SaveCooldown(ctx context.Context, signature string, anomalyID, repeatCount int) error
	PruneHistory(ctx context.Context, logDays, anomalyDays int) error
}

// Detector runs the rules engine on a schedule and records anomalies.
type Detector struct {
	Store detectorStore
	Rules *config.File[rules.RulesFile]
	// LogRetentionDays / AnomalyRetentionDays: 0 disables that table's prune.
	LogRetentionDays     int
	AnomalyRetentionDays int
	// Notify, if set, is called for each newly inserted anomaly.
	Notify func(severity, description string, anomalyID int)
	// OnHits is called with each detection round's hits (for the TUI).
	OnHits func([]rules.Hit)
	// RecordErrors counts individual detections that failed to persist.
	RecordErrors int
}

// Run detects until ctx is cancelled.
func (d *Detector) Run(ctx context.Context) error {
	interval := WindowInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastPrune time.Time
	for {
		// Reload rules each round so TUI edits take effect without a restart.
		if changed, err := d.Rules.Reload(); err != nil {
			log.Printf("detector: rules reload failed, keeping previous rules: %v", err)
		} else if changed {
			log.Print("detector: rules reloaded")
		}

		if time.Since(lastPrune) >= RetentionPeriod {
			if err := d.Store.PruneHistory(ctx, d.LogRetentionDays, d.AnomalyRetentionDays); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				log.Printf("detector: prune failed: %v", err)
			}
			lastPrune = time.Now()
		}

		if err := d.detectOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("detector: round failed: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// detectOnce runs one detection round.
func (d *Detector) detectOnce(ctx context.Context) error {
	rf, ok := d.Rules.Current()
	if !ok {
		return errors.New("no rules loaded")
	}

	rows, err := d.Store.QueryWindow(ctx, WindowSize)
	if err != nil {
		return err
	}
	entries := make([]*parser.Entry, len(rows))
	for i, r := range rows {
		entries[i] = fromStore(r)
	}

	window := WindowSize
	if rf.WindowSeconds > 0 {
		window = rf.WindowSeconds
	}
	hits := rules.Detect(entries, rf, window)
	rules.SortBySeverity(hits)
	if d.OnHits != nil {
		d.OnHits(hits)
	}

	for _, hit := range hits {
		if ctx.Err() != nil {
			return nil
		}
		// A single failed write must not suppress the other detections in this
		// window: log it and continue, so one bad row cannot hide an attack.
		if err := d.recordHit(ctx, hit, window); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("detector: recording %s failed: %v", hit.Type, err)
			d.RecordErrors++
		}
	}
	return nil
}

// recordHit writes a hit, merging repeats into the existing anomaly within the
// cooldown so a sustained condition does not flood the table.
func (d *Detector) recordHit(ctx context.Context, hit rules.Hit, window int) error {
	signature := cooldownSignature(hit)
	cooldown := d.cooldownFor(hit)

	existing, err := d.Store.GetCooldown(ctx, signature)
	if err != nil {
		return err
	}
	if existing != nil && existing.AgeSeconds < float64(cooldown) {
		repeat := existing.RepeatCount + 1
		if err := d.Store.BumpAnomaly(ctx, existing.AnomalyID, repeat); err != nil {
			return err
		}
		return d.Store.SaveCooldown(ctx, signature, existing.AnomalyID, repeat)
	}

	anomaly := makeAnomaly(hit, len(hit.Entity), window)
	id, err := d.Store.InsertAnomaly(ctx, anomaly, window)
	if err != nil {
		return err
	}
	if err := d.Store.SaveCooldown(ctx, signature, id, 1); err != nil {
		return err
	}
	log.Printf("DETECTOR %s", anomaly.Description)
	if d.Notify != nil {
		d.Notify(anomaly.Severity, anomaly.Description, id)
	}
	return nil
}

func (d *Detector) cooldownFor(hit rules.Hit) int {
	if rf, ok := d.Rules.Current(); ok {
		if override := lookupCooldown(rf, hit.Type); override > 0 {
			return override
		}
	}
	switch hit.Type {
	case "FLOOD", "HIGH_DROP_RATE":
		return FloodCooldown
	}
	return InsertCooldown
}

func lookupCooldown(rf rules.RulesFile, name string) int {
	for _, r := range rf.Rules {
		if r.Name == name {
			return r.CooldownSeconds
		}
	}
	return 0
}

// cooldownSignature identifies a (detection type, entity) pair.
func cooldownSignature(hit rules.Hit) string {
	entity := hit.Entity
	if entity == "" {
		if hit.SrcIP != nil {
			entity = *hit.SrcIP
		} else {
			entity = "-"
		}
	}
	return hit.Type + "|" + entity
}

// makeAnomaly builds the database row, including the stable JSON features the
// TUI and analytics read instead of parsing descriptions.
func makeAnomaly(hit rules.Hit, _ int, window int) store.Anomaly {
	features := map[string]any{
		"type":           hit.Type,
		"window_seconds": window,
		"repeat_count":   1,
	}
	if hit.Entity != "" {
		features["entity"] = hit.Entity
	} else {
		features["entity"] = nil
	}
	raw, err := json.Marshal(features)
	if err != nil {
		raw = []byte(`{}`)
	}
	return store.Anomaly{
		Severity:     hit.Severity,
		Description:  fmt.Sprintf("[RULE] %s", hit.Description),
		AnomalyScore: nil,
		Features:     raw,
	}
}

// EntryFromStore converts a database row back into a parser entry for
// detection and previewing.
func EntryFromStore(r *store.LogEntry) *parser.Entry {
	return fromStore(r)
}

// fromStore converts a database row back into a parser entry for detection.
func fromStore(r *store.LogEntry) *parser.Entry {
	deref := func(p *int) *int { return p }
	derefStr := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return &parser.Entry{
		Timestamp:      r.Timestamp.Format(time.RFC3339),
		Hostname:       r.Hostname,
		Facility:       r.Facility,
		Severity:       r.Severity,
		DeviceType:     r.DeviceType,
		Event:          r.Event,
		SrcIP:          derefStr(r.SrcIP),
		DstIP:          derefStr(r.DstIP),
		Proto:          r.Proto,
		DstPort:        deref(r.DstPort),
		SrcPort:        deref(r.SrcPort),
		Action:         r.Action,
		MAC:            r.MAC,
		VLANID:         deref(r.VLANID),
		IfName:         r.IfName,
		PeerIfName:     r.PeerIfName,
		STPRoot:        r.STPRoot,
		ClientMAC:      r.ClientMAC,
		SSID:           r.SSID,
		Radio:          r.Radio,
		Reason:         deref(r.Reason),
		SignalDBM:      deref(r.SignalDBM),
		TxRateMbps:     deref(r.TxRateMbps),
		EAPStatus:      r.EAPStatus,
		OSPFNbr:        derefStr(r.OSPFNbr),
		Gateway:        derefStr(r.Gateway),
		RouteDst:       r.RouteDst,
		DHCPMAC:        r.DHCPMAC,
		ConntrackCount: deref(r.ConntrackCt),
		RawLine:        r.RawLine,
	}
}
