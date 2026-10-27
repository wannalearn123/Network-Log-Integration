package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"siskamlan/internal/config"
	"siskamlan/internal/parser"
	"siskamlan/internal/rules"
	"siskamlan/internal/store"
)

// fakeDetectorStore records the detector's database interactions.
type fakeDetectorStore struct {
	rows []*store.LogEntry

	cooldowns map[string]*store.Cooldown

	inserted    []store.Anomaly
	nextID      int
	bumped      []int
	saved       []savedCooldown
	insertCalls int
	pruneCalls  int

	queryErr error
}

type savedCooldown struct {
	signature string
	id        int
	repeat    int
}

func newFakeDetectorStore() *fakeDetectorStore {
	return &fakeDetectorStore{cooldowns: map[string]*store.Cooldown{}, nextID: 100}
}

func (f *fakeDetectorStore) QueryWindow(ctx context.Context, windowSeconds int) ([]*store.LogEntry, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return f.rows, nil
}

func (f *fakeDetectorStore) InsertAnomaly(ctx context.Context, a store.Anomaly, windowSeconds int) (int, error) {
	f.insertCalls++
	f.inserted = append(f.inserted, a)
	id := f.nextID
	f.nextID++
	return id, nil
}

func (f *fakeDetectorStore) BumpAnomaly(ctx context.Context, anomalyID, repeatCount int) error {
	f.bumped = append(f.bumped, repeatCount)
	return nil
}

func (f *fakeDetectorStore) GetCooldown(ctx context.Context, signature string) (*store.Cooldown, error) {
	return f.cooldowns[signature], nil
}

func (f *fakeDetectorStore) SaveCooldown(ctx context.Context, signature string, anomalyID, repeatCount int) error {
	f.saved = append(f.saved, savedCooldown{signature, anomalyID, repeatCount})
	f.cooldowns[signature] = &store.Cooldown{
		AnomalyID: anomalyID, RepeatCount: repeatCount, AgeSeconds: 0,
	}
	return nil
}

func (f *fakeDetectorStore) PruneHistory(ctx context.Context, logDays, anomalyDays int) error {
	f.pruneCalls++
	return nil
}

// testRulesFile loads a rules file from a temp path.
func testRulesFile(t *testing.T) *config.File[rules.RulesFile] {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	raw, err := rules.Encode(rules.DefaultRulesFile())
	if err != nil {
		t.Fatalf("encode rules: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	f := config.NewFile[rules.RulesFile](path)
	f.Decode = rules.Decode
	f.Validate = rules.Validate
	if err := f.Load(); err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return f
}

func testDetector(t *testing.T, st detectorStore) *Detector {
	t.Helper()
	return &Detector{Store: st, Rules: testRulesFile(t)}
}

// TestRecordHitInsertsWhenNoCooldown covers the first-detection path.
func TestRecordHitInsertsWhenNoCooldown(t *testing.T) {
	fake := newFakeDetectorStore()
	d := testDetector(t, fake)

	var notified []string
	d.Notify = func(sev, desc string, id int) { notified = append(notified, desc) }

	hit := rules.Hit{Type: "PORT_SCAN", Severity: "HIGH", Entity: "10.0.0.5",
		Description: "Port scan from 10.0.0.5 — 20 ports in 30s"}

	if err := d.recordHit(context.Background(), hit, 30); err != nil {
		t.Fatalf("recordHit: %v", err)
	}
	if fake.insertCalls != 1 {
		t.Fatalf("insert calls = %d, want 1", fake.insertCalls)
	}
	if len(fake.saved) != 1 || fake.saved[0].repeat != 1 {
		t.Fatalf("cooldown saves = %+v, want repeat 1", fake.saved)
	}
	if len(notified) != 1 {
		t.Fatalf("notifications = %d, want 1", len(notified))
	}

	// Features must carry the structured type/entity analytics rely on.
	var feats map[string]any
	if err := json.Unmarshal(fake.inserted[0].Features, &feats); err != nil {
		t.Fatalf("features JSON: %v", err)
	}
	if feats["type"] != "PORT_SCAN" {
		t.Fatalf("features.type = %v", feats["type"])
	}
	if feats["entity"] != "10.0.0.5" {
		t.Fatalf("features.entity = %v", feats["entity"])
	}
}

// TestRecordHitMergesWithinCooldown covers the dedup path.
func TestRecordHitMergesWithinCooldown(t *testing.T) {
	fake := newFakeDetectorStore()
	d := testDetector(t, fake)

	hit := rules.Hit{Type: "PORT_SCAN", Severity: "HIGH", Entity: "10.0.0.5", Description: "x"}
	sig := cooldownSignature(hit)
	fake.cooldowns[sig] = &store.Cooldown{AnomalyID: 42, RepeatCount: 3, AgeSeconds: 10}

	notified := 0
	d.Notify = func(string, string, int) { notified++ }

	if err := d.recordHit(context.Background(), hit, 30); err != nil {
		t.Fatalf("recordHit: %v", err)
	}
	if fake.insertCalls != 0 {
		t.Fatalf("inserted a duplicate row; want merge")
	}
	if len(fake.bumped) != 1 || fake.bumped[0] != 4 {
		t.Fatalf("bumped = %v, want [4]", fake.bumped)
	}
	if notified != 0 {
		t.Fatalf("merged detection notified again")
	}
}

// TestRecordHitReinsertsAfterCooldownExpiry covers the expiry path.
func TestRecordHitReinsertsAfterCooldownExpiry(t *testing.T) {
	fake := newFakeDetectorStore()
	d := testDetector(t, fake)

	hit := rules.Hit{Type: "PORT_SCAN", Severity: "HIGH", Entity: "10.0.0.5", Description: "x"}
	fake.cooldowns[cooldownSignature(hit)] = &store.Cooldown{
		AnomalyID: 42, RepeatCount: 9, AgeSeconds: float64(InsertCooldown + 1),
	}

	if err := d.recordHit(context.Background(), hit, 30); err != nil {
		t.Fatalf("recordHit: %v", err)
	}
	if fake.insertCalls != 1 {
		t.Fatalf("insert calls = %d, want 1 after expiry", fake.insertCalls)
	}
	if len(fake.saved) != 1 || fake.saved[0].repeat != 1 {
		t.Fatalf("cooldown after expiry = %+v, want repeat 1", fake.saved)
	}
}

// TestFloodCooldownIsShorter checks the per-type cooldown override.
func TestFloodCooldownIsShorter(t *testing.T) {
	d := testDetector(t, newFakeDetectorStore())

	if got := d.cooldownFor(rules.Hit{Type: "FLOOD"}); got != FloodCooldown {
		t.Fatalf("FLOOD cooldown = %d, want %d", got, FloodCooldown)
	}
	if got := d.cooldownFor(rules.Hit{Type: "HIGH_DROP_RATE"}); got != FloodCooldown {
		t.Fatalf("HIGH_DROP_RATE cooldown = %d, want %d", got, FloodCooldown)
	}
	if got := d.cooldownFor(rules.Hit{Type: "PORT_SCAN"}); got != InsertCooldown {
		t.Fatalf("PORT_SCAN cooldown = %d, want %d", got, InsertCooldown)
	}
}

// TestPerRuleCooldownOverride checks cooldown_seconds from the rules file.
func TestPerRuleCooldownOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	rf := rules.RulesFile{Version: 1, WindowSeconds: 30, Rules: []rules.Rule{{
		Name: "CUSTOM", Severity: "HIGH", Rate: 1, CooldownSeconds: 7,
		Description: "custom",
	}}}
	raw, _ := rules.Encode(rf)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	f := config.NewFile[rules.RulesFile](path)
	f.Decode = rules.Decode
	f.Validate = rules.Validate
	if err := f.Load(); err != nil {
		t.Fatal(err)
	}

	d := &Detector{Store: newFakeDetectorStore(), Rules: f}
	if got := d.cooldownFor(rules.Hit{Type: "CUSTOM"}); got != 7 {
		t.Fatalf("cooldown = %d, want 7", got)
	}
}

// TestDetectOnceRecordsFlood runs one round end to end with synthetic rows.
func TestDetectOnceRecordsFlood(t *testing.T) {
	fake := newFakeDetectorStore()
	for i := 0; i < 240; i++ {
		fake.rows = append(fake.rows, &store.LogEntry{
			Event: "whatever", DeviceType: "other", RawLine: "x",
		})
	}
	d := testDetector(t, fake)

	var hits []rules.Hit
	d.OnHits = func(h []rules.Hit) { hits = h }

	if err := d.detectOnce(context.Background()); err != nil {
		t.Fatalf("detectOnce: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("no hits for 240 rows in a 30s window")
	}
	foundFlood := false
	for _, a := range fake.inserted {
		var feats map[string]any
		_ = json.Unmarshal(a.Features, &feats)
		if feats["type"] == "FLOOD" {
			foundFlood = true
		}
	}
	if !foundFlood {
		t.Fatalf("FLOOD anomaly not inserted; inserted=%d", len(fake.inserted))
	}
}

// TestDetectOncePropagatesQueryError checks errors reach the caller.
func TestDetectOncePropagatesQueryError(t *testing.T) {
	fake := newFakeDetectorStore()
	fake.queryErr = errFake
	d := testDetector(t, fake)
	if err := d.detectOnce(context.Background()); err == nil {
		t.Fatal("expected the query error to propagate")
	}
}

// TestCooldownSignatureFallsBackToSrcIP checks signature stability.
func TestCooldownSignatureFallsBackToSrcIP(t *testing.T) {
	ip := "10.9.9.9"
	hit := rules.Hit{Type: "FLOOD", Entity: "", SrcIP: &ip}
	if got := cooldownSignature(hit); got != "FLOOD|10.9.9.9" {
		t.Fatalf("signature = %q", got)
	}
	bare := rules.Hit{Type: "FLOOD"}
	if got := cooldownSignature(bare); got != "FLOOD|-" {
		t.Fatalf("signature = %q", got)
	}
}

// TestMakeAnomalyFeatures ensures required feature keys are present.
func TestMakeAnomalyFeatures(t *testing.T) {
	a := makeAnomaly(rules.Hit{Type: "STP_FLAP", Severity: "HIGH", Description: "d"}, 0, 30)
	var feats map[string]any
	if err := json.Unmarshal(a.Features, &feats); err != nil {
		t.Fatalf("features: %v", err)
	}
	for _, key := range []string{"type", "window_seconds", "repeat_count"} {
		if _, ok := feats[key]; !ok {
			t.Errorf("features missing %q", key)
		}
	}
	if a.AnomalyScore != nil {
		t.Error("rules must not invent a probability score")
	}
}

// TestEntryConversionRoundTrip checks store rows convert for detection.
func TestEntryConversionRoundTrip(t *testing.T) {
	port := 443
	src := "10.0.0.1"
	e := EntryFromStore(&store.LogEntry{
		Hostname: "h", DeviceType: "firewall", Event: "fw_block",
		SrcIP: &src, DstPort: &port, MAC: "aa:bb:cc:dd:ee:ff",
	})
	if e.SrcIP != src || e.DstPort == nil || *e.DstPort != port {
		t.Fatalf("conversion lost data: %+v", e)
	}
	if e.DeviceType != "firewall" || e.Event != "fw_block" {
		t.Fatalf("conversion lost metadata: %+v", e)
	}
}

var errFake = &fakeError{}

type fakeError struct{}

func (*fakeError) Error() string { return "fake error" }

// Compile-time check that a parsed entry is usable by the detector path.
var _ = parser.Parse
