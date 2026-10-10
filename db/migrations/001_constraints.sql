-- Apply once to an existing database. Fresh databases already have these checks.
-- NOT VALID preserves historical rows while enforcing constraints on new writes.
BEGIN;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'logs_dst_port_range' AND conrelid = 'logs'::regclass) THEN
        ALTER TABLE logs ADD CONSTRAINT logs_dst_port_range CHECK (dst_port BETWEEN 0 AND 65535) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'logs_src_port_range' AND conrelid = 'logs'::regclass) THEN
        ALTER TABLE logs ADD CONSTRAINT logs_src_port_range CHECK (src_port BETWEEN 0 AND 65535) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'logs_vlan_range' AND conrelid = 'logs'::regclass) THEN
        ALTER TABLE logs ADD CONSTRAINT logs_vlan_range CHECK (vlan_id BETWEEN 1 AND 4094) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'logs_conntrack_range' AND conrelid = 'logs'::regclass) THEN
        ALTER TABLE logs ADD CONSTRAINT logs_conntrack_range CHECK (conntrack_count >= 0) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'anomalies_severity_valid' AND conrelid = 'anomalies'::regclass) THEN
        ALTER TABLE anomalies ADD CONSTRAINT anomalies_severity_valid CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'anomalies_window_order' AND conrelid = 'anomalies'::regclass) THEN
        ALTER TABLE anomalies ADD CONSTRAINT anomalies_window_order CHECK (window_end >= window_start) NOT VALID;
    END IF;
END $$;
COMMIT;

BEGIN;
CREATE INDEX IF NOT EXISTS idx_logs_timestamp_device ON logs (timestamp, device_type);
CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp_severity ON anomalies (timestamp, severity);
CREATE INDEX IF NOT EXISTS idx_anomalies_features_gin ON anomalies USING GIN (features);
CREATE TABLE IF NOT EXISTS detection_cooldowns (
    signature TEXT PRIMARY KEY,
    anomaly_id INTEGER NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE,
    repeat_count INTEGER NOT NULL DEFAULT 1 CHECK (repeat_count > 0),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_detection_cooldowns_last_seen ON detection_cooldowns (last_seen);
COMMIT;
