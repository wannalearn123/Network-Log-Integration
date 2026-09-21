# Rule-based anomaly detection engine — deterministic pattern matching, no ML.
# Thresholds are rates (per second) so any window size scores the same.
# 30s equivalents: 12 ports / 12 fails / 210 events / 100 drops.
# Adjusted for realistic traffic: 99%+ normal, <1% attacks.

from collections import defaultdict


THRESHOLD_VERSION = "v3-realistic"
PORT_SCAN_RATE = 0.4     # >=12 unique ports in 30s (was 0.2 / 6 ports)
BRUTE_RATE = 0.4         # >=12 fails in 30s (was 0.2 / 6 fails)
DEAUTH_RATE = 0.3        # >=9 deauths in 30s, deauth-only (no auth failures mixed in)
FLOOD_RATE = 8.0         # >=240 events in 30s (was 7.0 / 210 events — reduced false positives)
DROP_RATE = 3.3333       # >=100 drops in 30s (was 0.367 / 11 drops)


    # Analyze log rows for known attack patterns. Returns list of hit dicts.
def detect_rules(rows, window_seconds=30):
    window_seconds = max(1, int(window_seconds or 30))
    hits = []

    # Rule 1: Port scan — same src_ip, high unique-port rate
    ip_ports = defaultdict(set)
    for row in rows:
        if row.get("src_ip") is not None and row.get("dst_port") is not None:
            ip_ports[str(row["src_ip"])].add(row["dst_port"])
    for ip, ports in ip_ports.items():
        if len(ports) / window_seconds >= PORT_SCAN_RATE:
            hits.append({
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "description": f"Port scan from {ip} — {len(ports)} ports in {window_seconds}s",
                "src_ip": ip,
            })

    # Rule 2: Brute force (auth failures only) + separate deauth storm.
    # DEAUTH alone is normal WiFi roaming — never CRITICAL by itself.
    # Also detects repeated fw_block to sensitive ports (SSH/HTTP) as brute force.
    ip_fails = defaultdict(int)
    ip_deauth = defaultdict(int)
    SENSITIVE_PORTS = {22, 443, 3389, 21, 23}  # SSH, HTTPS, RDP, FTP, Telnet (NOT 80 — DDoS target)
    for row in rows:
        ev = (row.get("event") or "").upper()
        src = row.get("src_ip")
        if not src or str(src).lower() in ("unknown", "none", ""):
            continue
        s = str(src)
        # Explicit brute force / auth failure events
        if "BRUTE" in ev or "AUTH_FAILURE" in ev or ("FAILED" in ev and "AUTH" in ev):
            ip_fails[s] += 1
        # Repeated fw_block to sensitive ports = likely brute force
        elif "FW_BLOCK" in ev or "BLOCK" in ev:
            dst_port = row.get("dst_port")
            if dst_port and int(dst_port) in SENSITIVE_PORTS:
                ip_fails[s] += 1
        if "DEAUTH" in ev:
            ip_deauth[s] += 1
    for ip, count in ip_fails.items():
        if count / window_seconds >= BRUTE_RATE:
            hits.append({
                "type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "description": f"Brute force from {ip} — {count} fails in {window_seconds}s",
                "src_ip": ip,
            })
    for ip, count in ip_deauth.items():
        if ip in ip_fails:
            continue  # already covered by brute-force above
        if count / window_seconds >= DEAUTH_RATE:
            hits.append({
                "type": "DEAUTH_STORM",
                "severity": "MEDIUM",
                "description": f"Deauth storm from {ip} — {count} in {window_seconds}s",
                "src_ip": ip,
            })

    # Rule 3: Traffic flood — event rate
    if len(rows) / window_seconds >= FLOOD_RATE:
        hits.append({
            "type": "FLOOD",
            "severity": "HIGH",
            "description": f"Traffic flood — {len(rows)} events in {window_seconds}s",
            "src_ip": None,
        })

    # Rule 4: High drop rate — drop rate (parser emits lowercase fw_block)
    drop_count = sum(
        1 for r in rows
        if (r.get("event") or "").upper() in ("FW_DROP", "FW_BLOCK")
    )
    if drop_count / window_seconds >= DROP_RATE:
        hits.append({
            "type": "HIGH_DROP_RATE",
            "severity": "MEDIUM",
            "description": f"High firewall drop rate — {drop_count} drops in {window_seconds}s",
            "src_ip": None,
        })

    return hits
