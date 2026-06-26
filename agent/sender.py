"""
Agent Sender
============
Handles all HTTP communication between the local agent and the FastAPI backend.

Features:
- Auto-registers the device on first contact
- Periodic heartbeat thread
- In-memory event queue with configurable batch flush
- Exponential-backoff retry queue
- Offline JSONL buffer — events are persisted locally when the backend is
  unreachable and replayed once connectivity is restored
"""

import json
import logging
import os
import platform
import socket
import threading
import time
import uuid
from collections import deque
from typing import Any, Dict, List, Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    raise SystemExit("requests is required: pip install requests")

import config

logger = logging.getLogger("agent.sender")

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_session() -> requests.Session:
    """Creates a requests Session with connection-level retry (not our app retry)."""
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"Content-Type": "application/json"})
    return session


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_mac() -> str:
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return ":".join(mac[i:i+2] for i in range(0, 12, 2))


# ─────────────────────────────────────────────────────────────────────────────
# AgentSender class
# ─────────────────────────────────────────────────────────────────────────────

class AgentSender:
    """
    Thread-safe event sender.

    Usage:
        sender = AgentSender()
        sender.start()          # starts heartbeat + flush threads
        sender.enqueue(event)   # non-blocking
        sender.stop()           # graceful shutdown
    """

    def __init__(self):
        self._session = _build_session()
        self._queue: deque = deque()        # pending events
        self._retry_queue: deque = deque()  # events that failed at least once
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._registered = False

    # ── Public API ───────────────────────────────────────────────────────────

    def enqueue(self, log_type: str, action: str, details: Optional[Dict] = None) -> None:
        """Add a single log event to the in-memory send queue (non-blocking)."""
        event = {
            "device_id": config.DEVICE_ID,
            "type": log_type,
            "action": action,
            "details": details or {},
        }
        with self._lock:
            self._queue.append(event)
        logger.debug("Enqueued event type=%s action=%s", log_type, action)

    def start(self) -> None:
        """Register device then start background threads."""
        self._register_device()
        self._replay_offline_buffer()

        threading.Thread(target=self._heartbeat_loop, daemon=True,
                         name="agent-heartbeat").start()
        threading.Thread(target=self._flush_loop, daemon=True,
                         name="agent-flush").start()
        threading.Thread(target=self._retry_loop, daemon=True,
                         name="agent-retry").start()
        logger.info("AgentSender started (device_id=%s)", config.DEVICE_ID)

    def stop(self) -> None:
        """Signal threads to stop then flush remaining events."""
        self._stop_event.set()
        self._flush()
        logger.info("AgentSender stopped")

    # ── Device registration ──────────────────────────────────────────────────

    def _register_device(self) -> bool:
        payload = {
            "id": config.DEVICE_ID,
            "hostname": config.HOSTNAME,
            "ip_address": _get_local_ip(),
            "mac_address": _get_mac(),
            "os_type": platform.system(),
            "firewall_status": self._get_firewall_status(),
        }
        for attempt in range(config.MAX_RETRY_ATTEMPTS):
            try:
                r = self._session.post(
                    f"{config.BACKEND_URL}/devices/register",
                    json=payload,
                    timeout=10,
                )
                if r.status_code in (200, 201):
                    self._registered = True
                    logger.info("Device registered: %s", config.DEVICE_ID)
                    return True
                logger.warning("Registration status %d: %s", r.status_code, r.text[:200])
            except requests.RequestException as exc:
                logger.warning("Registration attempt %d failed: %s", attempt + 1, exc)
                time.sleep(config.RETRY_BASE_DELAY_SEC * (2 ** attempt))
        logger.error("Could not register device after %d attempts — continuing offline",
                     config.MAX_RETRY_ATTEMPTS)
        return False

    @staticmethod
    def _get_firewall_status() -> str:
        """Best-effort Windows firewall status check."""
        if platform.system() != "Windows":
            return "unknown"
        try:
            import subprocess
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5
            )
            if "ON" in result.stdout.upper():
                return "enabled"
            return "disabled"
        except Exception:
            return "unknown"

    # ── Heartbeat ────────────────────────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._send_heartbeat()
            except Exception as exc:
                logger.warning("Heartbeat error: %s", exc)
            self._stop_event.wait(config.HEARTBEAT_INTERVAL_SEC)

    def _send_heartbeat(self) -> None:
        payload = {
            "status": "online",
            "firewall_status": self._get_firewall_status(),
        }
        r = self._session.post(
            f"{config.BACKEND_URL}/devices/{config.DEVICE_ID}/heartbeat",
            json=payload,
            timeout=10,
        )
        if r.status_code == 200:
            logger.debug("Heartbeat OK")
        else:
            logger.warning("Heartbeat failed: %d", r.status_code)

    # ── Flush loop ───────────────────────────────────────────────────────────

    def _flush_loop(self) -> None:
        while not self._stop_event.is_set():
            self._flush()
            self._stop_event.wait(config.BATCH_INTERVAL_SEC)

    def _flush(self) -> None:
        """Drain up to BATCH_SIZE events from queue and POST them."""
        with self._lock:
            if not self._queue:
                return
            batch: List[Dict] = []
            for _ in range(min(config.BATCH_SIZE, len(self._queue))):
                batch.append(self._queue.popleft())

        if not batch:
            return

        success = self._post_batch(batch)
        if not success:
            # Move to retry queue AND write to offline buffer
            with self._lock:
                for event in batch:
                    self._retry_queue.append((event, 0))
            self._write_offline_buffer(batch)

    def _post_batch(self, batch: List[Dict]) -> bool:
        """POST a batch of events. Returns True on success."""
        # Try the batch endpoint first; fall back to individual posts
        try:
            r = self._session.post(
                f"{config.BACKEND_URL}/threats/logs/batch",
                json={"events": batch},
                timeout=15,
            )
            if r.status_code in (200, 201):
                logger.info("Batch of %d events sent successfully", len(batch))
                return True
            logger.warning("Batch endpoint returned %d — falling back to individual", r.status_code)
        except requests.RequestException:
            logger.warning("Batch endpoint unreachable — falling back to individual POSTs")

        # Fallback: post one by one
        all_ok = True
        for event in batch:
            try:
                r = self._session.post(
                    f"{config.BACKEND_URL}/threats/logs",
                    json=event,
                    timeout=10,
                )
                if r.status_code not in (200, 201):
                    all_ok = False
            except requests.RequestException:
                all_ok = False
        return all_ok

    # ── Retry loop ───────────────────────────────────────────────────────────

    def _retry_loop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(30)  # wait before attempting retries
            self._process_retries()

    def _process_retries(self) -> None:
        with self._lock:
            if not self._retry_queue:
                return
            items = list(self._retry_queue)
            self._retry_queue.clear()

        still_failing = []
        for event, attempts in items:
            if attempts >= config.MAX_RETRY_ATTEMPTS:
                logger.error("Dropping event after %d attempts: %s", attempts, event.get("type"))
                continue
            delay = config.RETRY_BASE_DELAY_SEC * (2 ** attempts)
            time.sleep(min(delay, 30))
            ok = self._post_batch([event])
            if not ok:
                still_failing.append((event, attempts + 1))
            else:
                logger.info("Retry succeeded for event: %s", event.get("type"))

        with self._lock:
            for item in still_failing:
                self._retry_queue.append(item)

    # ── Offline buffer ───────────────────────────────────────────────────────

    def _write_offline_buffer(self, events: List[Dict]) -> None:
        try:
            with open(config.OFFLINE_BUFFER_PATH, "a", encoding="utf-8") as f:
                for event in events:
                    f.write(json.dumps(event) + "\n")
            logger.info("Wrote %d events to offline buffer", len(events))
        except OSError as exc:
            logger.error("Failed to write offline buffer: %s", exc)

    def _replay_offline_buffer(self) -> None:
        if not os.path.exists(config.OFFLINE_BUFFER_PATH):
            return
        events = []
        try:
            with open(config.OFFLINE_BUFFER_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read offline buffer: %s", exc)
            return

        if not events:
            return

        logger.info("Replaying %d buffered offline events", len(events))
        ok = self._post_batch(events)
        if ok:
            # Clear buffer after successful replay
            try:
                os.remove(config.OFFLINE_BUFFER_PATH)
                logger.info("Offline buffer cleared after successful replay")
            except OSError:
                pass
        else:
            logger.warning("Replay failed — buffer retained for next startup")


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton — all watcher modules import this
# ─────────────────────────────────────────────────────────────────────────────
sender = AgentSender()
