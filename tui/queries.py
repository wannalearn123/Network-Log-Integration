# SQL queries for the TUI dashboard.

SQL_LOGS = """
SELECT timestamp, hostname, device_type, event,
       src_ip, dst_ip, proto, dst_port
FROM logs
ORDER BY timestamp DESC
LIMIT 80
"""

SQL_LOGS_SEARCH = """
SELECT timestamp, hostname, device_type, event,
       src_ip, dst_ip, proto, dst_port
FROM logs
WHERE hostname ILIKE %s
   OR device_type ILIKE %s
   OR event ILIKE %s
   OR src_ip::text ILIKE %s
   OR dst_ip::text ILIKE %s
   OR proto ILIKE %s
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
WHERE description ILIKE %s
   OR severity ILIKE %s
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
