# Rule-based anomaly detection engine — deterministic pattern matching, no ML.
# Thresholds are rates (per second) so any window size scores the same;
# per-threshold 30s equivalents live next to each constant below.
# Adjusted for realistic traffic: 99%+ normal, <1% attacks.

from collections import defaultdict
import re


THRESHOLD_VERSION = "v4-attr"
PORT_SCAN_RATE = 0.4     # >=12 unique ports in 30s
BRUTE_RATE = 0.4         # >=12 fails in 30s
DEAUTH_RATE = 0.3        # >=9 deauths in 30s, deauth-only (no auth failures mixed in)
FLOOD_RATE = 8.0         # >=240 events in 30s
DROP_RATE = 3.3333       # >=100 drops in 30s
MAC_FLAP_RATE = 0.1      # >=3 flaps of the same MAC in 30s
STP_RATE = 2 / 30        # >=2 STP root changes in 30s
ROUTE_CHURN_RATE = 0.2   # >=6 route updates in 30s

SENSITIVE_PORTS = {22, 443, 3389, 21, 23}  # SSH, HTTPS, RDP, FTP, Telnet (NOT 80 — DDoS target)


_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _identity(row):
    """Attributed identity: AP -> client_mac, switch -> mac, else src_ip."""
    device = (row.get("device_type") or "")
    if device == "ap":
        cm = row.get("client_mac")
        return str(cm) if cm else None
    if device == "switch":
        m = row.get("mac")
        return str(m) if m else None
    src = row.get("src_ip")
    if not src or str(src).lower() in ("unknown", "none", ""):
        return None
    return str(src)


def detect_rules(rows, window_seconds=30):
    """Match log rows against known attack patterns. Returns list of hits."""
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
                "entity": ip,
            })

    # Rule 2: Brute force (auth failures only) + separate deauth storm.
    # DEAUTH alone is normal WiFi roaming — never CRITICAL by itself.
    # Also detects repeated fw_block to sensitive ports (SSH/HTTP) as brute force.
    # AP auth failures attribute to client_mac; firewall to src_ip.
    ip_fails = defaultdict(int)
    ip_deauth = defaultdict(int)
    for row in rows:
        ev = (row.get("event") or "").upper()
        ent = _identity(row)
        if not ent:
            continue
        # Explicit brute force / auth failure events
        if "BRUTE" in ev or "AUTH_FAILURE" in ev or ("FAILED" in ev and "AUTH" in ev):
            ip_fails[ent] += 1
        # Repeated fw_block to sensitive ports = likely brute force
        elif "FW_BLOCK" in ev or "BLOCK" in ev:
            dst_port = row.get("dst_port")
            if dst_port and int(dst_port) in SENSITIVE_PORTS:
                ip_fails[ent] += 1
        if "DEAUTH" in ev:
            ip_deauth[ent] += 1
    for ent, count in ip_fails.items():
        if count / window_seconds >= BRUTE_RATE:
            hits.append({
                "type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "description": f"Brute force from {ent} — {count} fails in {window_seconds}s",
                "src_ip": ent if _IPV4_RE.match(ent) else None,
                "entity": ent,
            })
    for ent, count in ip_deauth.items():
        if ip_fails.get(ent, 0) / window_seconds >= BRUTE_RATE:
            continue  # already covered by brute-force above
        if count / window_seconds >= DEAUTH_RATE:
            hits.append({
                "type": "DEAUTH_STORM",
                "severity": "MEDIUM",
                "description": f"Deauth storm from {ent} — {count} in {window_seconds}s",
                "src_ip": None,
                "entity": ent,
            })

    # Rule 3: Traffic flood — event rate
    if len(rows) / window_seconds >= FLOOD_RATE:
        hits.append({
            "type": "FLOOD",
            "severity": "HIGH",
            "description": f"Traffic flood — {len(rows)} events in {window_seconds}s",
            "src_ip": None,
            "entity": None,
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
            "entity": None,
        })

    # Rule 5: MAC flap storm — same MAC flapping repeatedly (loop/spoof/MITM).
    mac_flaps = defaultdict(list)
    for row in rows:
        if (row.get("event") or "").upper() == "MAC_FLAP":
            m = row.get("mac") or _identity(row)
            if m:
                mac_flaps[str(m)].append(row)
    for mac, rs in mac_flaps.items():
        if len(rs) / window_seconds >= MAC_FLAP_RATE:
            vlan = rs[0].get("vlan_id")
            ports = sorted({str(r.get("ifname") or "?") for r in rs} |
                           {str(r.get("peer_ifname") or "?") for r in rs} - {"?"})
            detail = f" (vlan {vlan})" if vlan else ""
            pdetail = f" between {'/'.join(ports)}" if ports else ""
            hits.append({
                "type": "MAC_FLAP",
                "severity": "HIGH",
                "description": f"MAC flap storm {mac}{detail} — {len(rs)} flaps in {window_seconds}s{pdetail}",
                "src_ip": None,
                "entity": mac,
            })

    # Rule 6: STP instability — repeated root changes (rogue root / loop).
    stp_rows = [r for r in rows if (r.get("event") or "").upper() == "STP_EVENT"]
    if len(stp_rows) / window_seconds >= STP_RATE:
        roots = sorted({str(r.get("stp_root") or r.get("ifname") or "?") for r in stp_rows} - {"?"})
        rdetail = f" (root {', '.join(roots)})" if roots else ""
        hits.append({
            "type": "STP_FLAP",
            "severity": "HIGH",
            "description": f"STP instability — {len(stp_rows)} root changes in {window_seconds}s{rdetail}",
            "src_ip": None,
            "entity": None,
        })

    # Rule 7: Route churn — repeated route/OSPF updates (hijack / flapping peer).
    rt_rows = [r for r in rows
               if (r.get("event") or "").upper() in ("ROUTE_UPDATE", "ROUTE_CHANGE")]
    if len(rt_rows) / window_seconds >= ROUTE_CHURN_RATE:
        nbrs = sorted({str(r.get("ospf_nbr") or r.get("gateway") or "?") for r in rt_rows} - {"?"})
        ndetail = f" (peer {', '.join(nbrs)})" if nbrs else ""
        hits.append({
            "type": "ROUTE_CHURN",
            "severity": "MEDIUM",
            "description": f"Route churn — {len(rt_rows)} updates in {window_seconds}s{ndetail}",
            "src_ip": None,
            "entity": None,
        })

    return hits
