# Telegram alert notifier — fires on fresh HIGH/CRITICAL anomaly inserts.
#
# Env config (.env):
#   NOTIFY_TELEGRAM=1            master switch
#   TELEGRAM_BOT_TOKEN=...       bot token from @BotFather
#   TELEGRAM_CHAT_ID=...         target chat id (@userinfobot / getUpdates)
#   NOTIFY_MIN_SEVERITY=HIGH     LOW | MEDIUM | HIGH | CRITICAL
#   TELEGRAM_API_BASE=...        optional override (proxy/testing)
#
# Never raises: notification failures must not crash the detector.

import json
import os
import sys
import time
import urllib.request

SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

DEFAULT_API_BASE = "https://api.telegram.org"
TIMEOUT_SECONDS = 5


def _log(msg):
    print(f"[NOTIFY] {msg}", file=sys.stderr)


def _enabled():
    return os.environ.get("NOTIFY_TELEGRAM", "").strip().lower() in ("1", "true", "yes")


def _min_severity():
    return os.environ.get("NOTIFY_MIN_SEVERITY", "HIGH").strip().upper()


def _send_telegram(text):
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        _log("Telegram not configured (missing TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID) — skipping")
        return False

    api_base = os.environ.get("TELEGRAM_API_BASE", DEFAULT_API_BASE).rstrip("/")
    url = f"{api_base}/bot{token}/sendMessage"
    payload = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8", "replace")
            if resp.status != 200:
                _log(f"Telegram API returned HTTP {resp.status}: {body[:200]}")
                return False
            data = json.loads(body)
            if not data.get("ok"):
                _log(f"Telegram API error: {body[:200]}")
                return False
            return True
    except Exception as e:
        _log(f"Telegram send failed: {e}")
        return False


def notify(severity, description, anomaly_id, timestamp=None):
    """Send an alert for a fresh anomaly. No-op when disabled/unconfigured."""
    if not _enabled():
        return
    if SEV_RANK.get(severity, 0) < SEV_RANK.get(_min_severity(), 2):
        return

    ts = timestamp or time.strftime("%Y-%m-%d %H:%M:%S")
    text = (
        f"🚨 SISKAMLAN ALERT [{severity}]\n"
        f"Time: {ts}\n"
        f"ID: {anomaly_id}\n"
        f"{description}"
    )
    _send_telegram(text)
