import os
import threading
import tempfile
import time
from pathlib import Path
import unittest
from unittest.mock import patch, Mock

from pipeline.rules_engine import detect_rules
from pipeline.anomaly_detector import merge_signature, make_anomaly
from pipeline.notifier import notify, _min_severity
from db.init import get_connection_retry, prune_history
import psycopg2
from pipeline.orchestrator import tail_files


class RulesTests(unittest.TestCase):
    def test_stp_exact_boundary(self):
        rows = [{"event": "stp_event"}] * 2
        self.assertIn("STP_FLAP", {h["type"] for h in detect_rules(rows)})
        self.assertNotIn("STP_FLAP", {h["type"] for h in detect_rules(rows[:1])})

    def test_single_auth_failure_does_not_hide_deauth_storm(self):
        base = {"device_type": "ap", "client_mac": "aa:bb:cc:dd:ee:ff"}
        rows = [dict(base, event="deauth")] * 9 + [dict(base, event="auth_failure")]
        self.assertEqual([h["type"] for h in detect_rules(rows)], ["DEAUTH_STORM"])

    def test_scan_boundary(self):
        rows = [{"src_ip": "192.0.2.1", "dst_port": p} for p in range(1, 13)]
        self.assertEqual(detect_rules(rows)[0]["type"], "PORT_SCAN")
        self.assertFalse(detect_rules(rows[:-1]))

    def test_signature_survives_minute_boundary(self):
        hit = {"type": "PORT_SCAN", "entity": "192.0.2.1"}
        with patch("time.time", return_value=59):
            first = merge_signature(hit)
        with patch("time.time", return_value=61):
            self.assertEqual(first, merge_signature(hit))

    def test_rules_have_no_fake_probability(self):
        hit = {"type": "FLOOD", "severity": "HIGH", "description": "burst"}
        self.assertIsNone(make_anomaly(hit, [])['anomaly_score'])


class ConfigurationTests(unittest.TestCase):
    @patch.dict(os.environ, {"NOTIFY_TELEGRAM": "1"}, clear=True)
    @patch("pipeline.notifier._deliver")
    def test_notification_default(self, deliver):
        notify("HIGH", "test", 1)
        for _ in range(20):
            if deliver.called:
                break
            time.sleep(0.01)
        deliver.assert_called_once()

    @patch.dict(os.environ, {"NOTIFY_MIN_SEVERITY": "garbage"}, clear=True)
    def test_invalid_severity_uses_high(self):
        self.assertEqual(_min_severity(), "HIGH")

    @patch("db.init.get_connection", side_effect=psycopg2.OperationalError)
    def test_retry_cancelled(self, connect):
        stop = threading.Event()
        stop.set()
        self.assertIsNone(get_connection_retry(stop))
        connect.assert_not_called()

    @patch.dict(os.environ, {"LOG_RETENTION_DAYS": "0", "ANOMALY_RETENTION_DAYS": "30"}, clear=True)
    def test_retention_can_disable_logs(self):
        cursor = Mock()
        prune_history(cursor)
        self.assertEqual(cursor.execute.call_count, 2)
        self.assertIn("DELETE FROM anomalies", cursor.execute.call_args_list[0].args[0])

    @patch("db.init.ensure_runtime_schema")
    @patch("db.init.get_connection")
    def test_connection_retry_initializes_runtime_schema(self, connect, ensure):
        connect.return_value = Mock()
        self.assertIsNotNone(get_connection_retry(threading.Event(), attempts=1))
        ensure.assert_called_once_with(connect.return_value)


class TailTests(unittest.TestCase):
    def test_new_file_partial_line_and_rotation(self):
        class Sink:
            def __init__(self):
                self.data = bytearray()
            def write(self, value):
                self.data.extend(value)
            def flush(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sink = Sink()
            stop = threading.Event()
            thread = threading.Thread(target=tail_files, args=(root, sink, stop))
            thread.start()
            try:
                time.sleep(0.15)  # Initial discovery finishes before new file creation.
                path = root / "device.log"
                path.write_bytes(b"partial")
                time.sleep(0.2)
                self.assertFalse(sink.data)
                with path.open("ab") as stream:
                    stream.write(b" completed\n")
                deadline = time.monotonic() + 2
                while b"completed\n" not in sink.data and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(sink.data, b"partial completed\n")
                path.rename(root / "device.old")
                path.write_bytes(b"rotated\n")
                deadline = time.monotonic() + 2
                while b"rotated\n" not in sink.data and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(sink.data, b"partial completed\nrotated\n")
            finally:
                stop.set()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())

    def test_tail_offset_resumes_after_restart(self):
        class Sink:
            def __init__(self):
                self.data = bytearray()
            def write(self, value):
                self.data.extend(value)
            def flush(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "device.log"
            path.write_bytes(b"first\n")
            state = root / "state" / "offsets.json"
            first_sink = Sink()
            stop = threading.Event()
            thread = threading.Thread(target=tail_files, args=(root, first_sink, stop, state))
            thread.start()
            try:
                time.sleep(0.2)
            finally:
                stop.set()
                thread.join(timeout=2)
            self.assertFalse(first_sink.data)  # pre-existing data starts at EOF
            with path.open("ab") as stream:
                stream.write(b"second\n")
            second_sink = Sink()
            stop = threading.Event()
            thread = threading.Thread(target=tail_files, args=(root, second_sink, stop, state))
            thread.start()
            try:
                deadline = time.monotonic() + 2
                while b"second\n" not in second_sink.data and time.monotonic() < deadline:
                    time.sleep(0.02)
            finally:
                stop.set()
                thread.join(timeout=2)
            self.assertEqual(second_sink.data, b"second\n")


if __name__ == "__main__":
    unittest.main()
