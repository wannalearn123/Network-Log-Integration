# Rule-based anomaly detection engine — deterministic pattern matching, no ML.

from collections import defaultdict


    # Analyze log rows for known attack patterns. Returns list of hit dicts.
def detect_rules(rows, window_seconds=30):
    hits = []

    # Rule 1: Port scan — same src_ip, >5 unique dst_ports
    ip_ports = defaultdict(set)
    for row in rows:
        if row.get("src_ip") and row.get("dst_port"):
            ip_ports[str(row["src_ip"])].add(row["dst_port"])
    for ip, ports in ip_ports.items():
        if len(ports) > 5:
            hits.append({
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "description": f"Port scan from {ip} — {len(ports)} unique ports",
                "src_ip": ip,
            })

    # Rule 2: Brute force — same src_ip, >5 failed events
    ip_fails = defaultdict(int)
    for row in rows:
        ev = (row.get("event") or "").upper()
        if "FAILED" in ev or "BRUTE" in ev or "DEAUTH" in ev or "AUTH_FAILURE" in ev:
            src = row.get("src_ip")
            if not src or str(src).lower() in ("unknown", "none", ""):
                continue
            ip_fails[str(src)] += 1
    for ip, count in ip_fails.items():
        if count > 5:
            hits.append({
                "type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "description": f"Brute force from {ip} — {count} failed attempts",
                "src_ip": ip,
            })

    # Rule 3: Traffic flood — >50 events in window
    if len(rows) > 50:
        hits.append({
            "type": "FLOOD",
            "severity": "HIGH",
            "description": f"Traffic flood — {len(rows)} events in {window_seconds}s",
            "src_ip": None,
        })

    # Rule 4: High drop rate — >10 drops (parser emits lowercase fw_block)
    drop_count = sum(
        1 for r in rows
        if (r.get("event") or "").upper() in ("FW_DROP", "FW_BLOCK")
    )
    if drop_count > 10:
        hits.append({
            "type": "HIGH_DROP_RATE",
            "severity": "MEDIUM",
            "description": f"High firewall drop rate — {drop_count} drops in {window_seconds}s",
            "src_ip": None,
        })

    return hits
