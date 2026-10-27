// Package rules implements a configurable, data-driven anomaly engine.
//
// A rule describes an aggregate over a time window: it filters rows, groups
// them, then compares a count or distinct-count rate against a threshold.
// Rules live in config/rules.yaml and are hot-reloaded by the detector.
package rules

// Condition is a boolean expression over a log row. Zero value matches all.
//
// Use All / Any / Not to nest; otherwise a leaf compares Field using Op.
type Condition struct {
	All []Condition `yaml:"all,omitempty" json:"all,omitempty"`
	Any []Condition `yaml:"any,omitempty" json:"any,omitempty"`
	Not *Condition  `yaml:"not,omitempty" json:"not,omitempty"`

	Field  string `yaml:"field,omitempty" json:"field,omitempty"`
	Op     string `yaml:"op,omitempty" json:"op,omitempty"`
	Value  any    `yaml:"value,omitempty" json:"value,omitempty"`
	Values []any  `yaml:"values,omitempty" json:"values,omitempty"`
}

// Rule is one aggregate detection.
type Rule struct {
	Name        string    `yaml:"name" json:"name"`
	Enabled     *bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Severity    string    `yaml:"severity" json:"severity"`
	Description string    `yaml:"description" json:"description"`
	When        Condition `yaml:"when,omitempty" json:"when,omitempty"`

	GroupBy    []string `yaml:"group_by,omitempty" json:"group_by,omitempty"`
	Count      string   `yaml:"count,omitempty" json:"count,omitempty"` // rows (default) | distinct
	DistinctOn string   `yaml:"distinct_on,omitempty" json:"distinct_on,omitempty"`

	// Rate is events per second, so any window size scores identically.
	Rate     float64 `yaml:"rate" json:"rate"`
	MinCount int     `yaml:"min_count,omitempty" json:"min_count,omitempty"`

	CooldownSeconds int      `yaml:"cooldown_seconds,omitempty" json:"cooldown_seconds,omitempty"`
	SuppressBy      []string `yaml:"suppress_by,omitempty" json:"suppress_by,omitempty"`
}

// IsEnabled defaults to true when the field is omitted.
func (r Rule) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// IsDistinct reports whether the rule counts distinct values.
func (r Rule) IsDistinct() bool { return r.Count == "distinct" }

// RulesFile is the on-disk document.
type RulesFile struct {
	Version       int    `yaml:"version" json:"version"`
	WindowSeconds int    `yaml:"window_seconds,omitempty" json:"window_seconds,omitempty"`
	Rules         []Rule `yaml:"rules" json:"rules"`
}

// Hit is one detection produced by the engine.
type Hit struct {
	Type        string
	Severity    string
	Description string
	Entity      string
	SrcIP       *string
}

// KnownFields lists the row fields usable in conditions and grouping. The
// synthetic "$" fields are computed per row.
var KnownFields = []string{
	"hostname", "facility", "severity", "device_type", "event",
	"src_ip", "dst_ip", "proto", "dst_port", "src_port", "action",
	"mac", "vlan_id", "ifname", "peer_ifname", "stp_root",
	"client_mac", "ssid", "radio", "reason", "signal_dbm",
	"tx_rate_mbps", "eap_status", "ospf_nbr", "gateway", "route_dst",
	"dhcp_mac", "conntrack_count",
	"$identity", "$mac",
}

// MetadataFields are descriptive columns that are not useful for grouping.
var nonGroupable = map[string]bool{"hostname": true, "facility": true, "severity": true}

// Severities in ascending order, used for sorting hits.
var Severities = []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
