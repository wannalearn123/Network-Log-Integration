-- SISKAMLAN (Sistem Keamanan LAN) — Database Schema

-- ============================================================
-- logs: parsed syslog entries from all network devices
-- ============================================================
CREATE TABLE IF NOT EXISTS logs (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL,
    hostname      VARCHAR(64),
    facility      VARCHAR(16),
    severity      VARCHAR(16),
    device_type   VARCHAR(32),
    event         VARCHAR(64),
    src_ip        INET,
    dst_ip        INET,
    proto         VARCHAR(8),
    dst_port      INTEGER,
    -- parsed detail fields; all nullable, omitted when unset
    src_port      INTEGER,
    action        VARCHAR(16),
    mac           VARCHAR(24),
    vlan_id       INTEGER,
    ifname        VARCHAR(40),
    peer_ifname   VARCHAR(40),
    stp_root      VARCHAR(40),
    client_mac    VARCHAR(24),
    ssid          VARCHAR(32),
    radio         VARCHAR(16),
    reason        INTEGER,
    signal_dbm    INTEGER,
    tx_rate_mbps  INTEGER,
    eap_status    VARCHAR(16),
    ospf_nbr      INET,
    gateway       INET,
    route_dst     VARCHAR(46),
    dhcp_mac      VARCHAR(24),
    conntrack_count INTEGER,
    raw_line      TEXT,
    parsed_at     TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT logs_dst_port_range CHECK (dst_port BETWEEN 0 AND 65535),
    CONSTRAINT logs_src_port_range CHECK (src_port BETWEEN 0 AND 65535),
    CONSTRAINT logs_vlan_range CHECK (vlan_id BETWEEN 1 AND 4094),
    CONSTRAINT logs_conntrack_range CHECK (conntrack_count >= 0)
);

-- ============================================================
-- anomalies: ML-detected anomalous behavior
-- ============================================================
CREATE TABLE IF NOT EXISTS anomalies (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL,
    window_start  TIMESTAMPTZ NOT NULL,
    window_end    TIMESTAMPTZ NOT NULL,
    anomaly_score FLOAT,
    features      JSONB,
    severity      VARCHAR(16),
    description   TEXT,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT anomalies_severity_valid CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT anomalies_window_order CHECK (window_end >= window_start)
);

-- ============================================================
-- Indexes
-- ============================================================
CREATE INDEX idx_logs_timestamp     ON logs (timestamp);
CREATE INDEX idx_logs_hostname      ON logs (hostname);
CREATE INDEX idx_logs_device_type   ON logs (device_type);
CREATE INDEX idx_logs_severity      ON logs (severity);
CREATE INDEX idx_logs_event         ON logs (event);
CREATE INDEX idx_logs_src_ip        ON logs (src_ip);
CREATE INDEX idx_logs_dst_ip        ON logs (dst_ip);
CREATE INDEX idx_logs_client_mac    ON logs (client_mac);
CREATE INDEX idx_logs_mac           ON logs (mac);

CREATE INDEX idx_anomalies_timestamp ON anomalies (timestamp);
CREATE INDEX idx_anomalies_severity  ON anomalies (severity);
CREATE INDEX idx_logs_timestamp_device ON logs (timestamp, device_type);
CREATE INDEX idx_anomalies_timestamp_severity ON anomalies (timestamp, severity);
CREATE INDEX idx_anomalies_features_gin ON anomalies USING GIN (features);

CREATE TABLE IF NOT EXISTS detection_cooldowns (
    signature       TEXT PRIMARY KEY,
    anomaly_id      INTEGER NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE,
    repeat_count    INTEGER NOT NULL DEFAULT 1 CHECK (repeat_count > 0),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_detection_cooldowns_last_seen ON detection_cooldowns (last_seen);
