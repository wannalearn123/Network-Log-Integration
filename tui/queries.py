# SQL queries for the TUI dashboard.

SQL_LOGS = """
SELECT timestamp, hostname, device_type, event,
       host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, proto, dst_port,
       COALESCE(client_mac, mac, host(dst_ip)) AS entity,
       src_port, action, tcp_flags, mac, vlan_id, ifname, peer_ifname,
       stp_root, client_mac, ssid, radio, reason, signal_dbm,
       tx_rate_mbps, eap_status, ospf_nbr, gateway, route_dst,
       dhcp_mac, conntrack_count
FROM logs
ORDER BY timestamp DESC
LIMIT 80
"""

SQL_LOGS_SEARCH = """
SELECT timestamp, hostname, device_type, event,
       host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, proto, dst_port,
       COALESCE(client_mac, mac, host(dst_ip)) AS entity,
       src_port, action, tcp_flags, mac, vlan_id, ifname, peer_ifname,
       stp_root, client_mac, ssid, radio, reason, signal_dbm,
       tx_rate_mbps, eap_status, ospf_nbr, gateway, route_dst,
       dhcp_mac, conntrack_count
FROM logs
WHERE hostname ILIKE %s ESCAPE '\\'
   OR device_type ILIKE %s ESCAPE '\\'
   OR event ILIKE %s ESCAPE '\\'
   OR src_ip::text ILIKE %s ESCAPE '\\'
   OR dst_ip::text ILIKE %s ESCAPE '\\'
   OR proto ILIKE %s ESCAPE '\\'
   OR client_mac ILIKE %s ESCAPE '\\'
   OR mac ILIKE %s ESCAPE '\\'
   OR ssid ILIKE %s ESCAPE '\\'
   OR ifname ILIKE %s ESCAPE '\\'
ORDER BY timestamp DESC
LIMIT 80
"""

SQL_ANOMALIES = """
SELECT id, timestamp, severity, anomaly_score, description
FROM anomalies
ORDER BY timestamp DESC
LIMIT 30
"""

SQL_ANOMALIES_SEARCH = """
SELECT id, timestamp, severity, anomaly_score, description
FROM anomalies
WHERE description ILIKE %s ESCAPE '\\'
   OR severity ILIKE %s ESCAPE '\\'
ORDER BY timestamp DESC
LIMIT 30
"""

SQL_STATS_LOGS = """
SELECT COUNT(*) AS total_logs,
       COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') AS logs_1h,
       COUNT(DISTINCT hostname) FILTER (WHERE timestamp >= NOW() - INTERVAL '5 minutes') AS active_devices
FROM logs
"""

SQL_STATS_ANOMALIES = """
SELECT COUNT(*) AS total_anomalies,
       COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') AS anomalies_1h,
       COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS sev_crit,
       COUNT(*) FILTER (WHERE severity = 'HIGH') AS sev_high,
       COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS sev_med,
       COUNT(*) FILTER (WHERE severity = 'LOW') AS sev_low
FROM anomalies
"""

SQL_SECURITY_SOURCES = """
SELECT
    (regexp_match(description, 'from ([0-9A-Za-z.:_-]+)'))[1] AS src_ip,
    COUNT(*) AS cnt
FROM anomalies
WHERE description ILIKE '%from %'
GROUP BY src_ip
ORDER BY cnt DESC
LIMIT 5
"""

SQL_SECURITY_DETECTIONS = """
SELECT
    CASE
        WHEN description ILIKE '%Port scan%' THEN 'Port Scan'
        WHEN description ILIKE '%Brute force%' THEN 'Brute Force'
        WHEN description ILIKE '%Traffic flood%' THEN 'Traffic Flood'
        WHEN description ILIKE '%Deauth storm%' THEN 'Deauth Storm'
        WHEN description ILIKE '%firewall drop%' THEN 'High Drop Rate'
        WHEN description ILIKE '%MAC flap%' THEN 'MAC Flap'
        WHEN description ILIKE '%STP instability%' THEN 'STP Flap'
        WHEN description ILIKE '%Route churn%' THEN 'Route Churn'
        ELSE 'Other'
    END AS detection_type,
    COUNT(*) AS cnt
FROM anomalies
GROUP BY detection_type
ORDER BY cnt DESC
"""
