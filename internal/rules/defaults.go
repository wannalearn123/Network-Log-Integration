package rules

// DefaultRulesFile is the shipped rule set, the data form of the original
// hardcoded engine. It is seeded into config/rules.yaml on first run.
//
// Thresholds are rates (events per second) so any window size scores the same;
// the 30-second equivalent is noted per rule.
func DefaultRulesFile() RulesFile {
	enabled := func() *bool { b := true; return &b }

	return RulesFile{
		Version:       1,
		WindowSeconds: 30,
		Rules: []Rule{
			{
				Name:        "PORT_SCAN",
				Enabled:     enabled(),
				Severity:    "HIGH",
				Description: "Port scan from {entity} — {count} ports in {window}s",
				When: Condition{All: []Condition{
					{Field: "src_ip", Op: "exists"},
					{Field: "dst_port", Op: "exists"},
				}},
				GroupBy:    []string{"src_ip"},
				Count:      "distinct",
				DistinctOn: "dst_port",
				Rate:       0.4, // >=12 unique ports in 30s
			},
			{
				Name:        "BRUTE_FORCE",
				Enabled:     enabled(),
				Severity:    "CRITICAL",
				Description: "Brute force from {entity} — {count} fails in {window}s",
				When: Condition{Any: []Condition{
					{Field: "event", Op: "contains_any", Values: []any{"BRUTE", "AUTH_FAILURE"}},
					{All: []Condition{
						{Field: "event", Op: "contains", Value: "FAILED"},
						{Field: "event", Op: "contains", Value: "AUTH"},
					}},
					// Repeated firewall blocks to sensitive ports look like brute force.
					{All: []Condition{
						{Field: "event", Op: "contains_any", Values: []any{"FW_BLOCK", "BLOCK"}},
						{Field: "dst_port", Op: "in", Values: []any{22, 443, 3389, 21, 23}},
					}},
				}},
				GroupBy: []string{"$identity"},
				Rate:    0.4, // >=12 fails in 30s
			},
			{
				Name:        "DEAUTH_STORM",
				Enabled:     enabled(),
				Severity:    "MEDIUM",
				Description: "Deauth storm from {entity} — {count} in {window}s",
				When:        Condition{Field: "event", Op: "contains", Value: "DEAUTH"},
				GroupBy:     []string{"$identity"},
				Rate:        0.3, // >=9 deauths in 30s
				// Deauth alone is normal roaming; suppress when the same entity
				// is already covered by a brute-force detection.
				SuppressBy: []string{"BRUTE_FORCE"},
			},
			{
				Name:        "FLOOD",
				Enabled:     enabled(),
				Severity:    "HIGH",
				Description: "Traffic flood — {count} events in {window}s",
				When:        Condition{},
				Rate:        8.0, // >=240 events in 30s
			},
			{
				Name:        "HIGH_DROP_RATE",
				Enabled:     enabled(),
				Severity:    "MEDIUM",
				Description: "High firewall drop rate — {count} drops in {window}s",
				When:        Condition{Field: "event", Op: "in", Values: []any{"FW_DROP", "FW_BLOCK"}},
				Rate:        3.3333, // >=100 drops in 30s
			},
			{
				Name:        "MAC_FLAP",
				Enabled:     enabled(),
				Severity:    "HIGH",
				Description: "MAC flap storm {entity} — {count} flaps in {window}s",
				When:        Condition{Field: "event", Op: "eq", Value: "MAC_FLAP"},
				GroupBy:     []string{"$mac"},
				Rate:        0.1, // >=3 flaps of the same MAC in 30s
			},
			{
				Name:        "STP_FLAP",
				Enabled:     enabled(),
				Severity:    "HIGH",
				Description: "STP instability — {count} root changes in {window}s",
				When:        Condition{Field: "event", Op: "eq", Value: "STP_EVENT"},
				Rate:        2.0 / 30.0, // >=2 STP root changes in 30s
			},
			{
				Name:        "ROUTE_CHURN",
				Enabled:     enabled(),
				Severity:    "MEDIUM",
				Description: "Route churn — {count} updates in {window}s",
				When:        Condition{Field: "event", Op: "in", Values: []any{"ROUTE_UPDATE", "ROUTE_CHANGE"}},
				Rate:        0.2, // >=6 route updates in 30s
			},
		},
	}
}
