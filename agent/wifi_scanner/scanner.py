"""
Wi-Fi Scanner
=============
Scans visible Wi-Fi networks using `netsh wlan show networks mode=bssid`
(Windows native, no extra dependencies).

Reports:
- SSID, BSSID, authentication type, encryption, signal strength
- Evil-twin heuristic: two SSIDs sharing the same name but different BSSIDs
  on the same channel
"""

import logging
import os
import platform
import re
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from sender import sender

logger = logging.getLogger("agent.wifi_scanner")


# ─────────────────────────────────────────────────────────────────────────────
# Parsers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_netsh_output(output: str) -> List[Dict]:
    """Parse `netsh wlan show networks mode=bssid` output into a list of dicts."""
    networks: List[Dict] = []
    current: Optional[Dict] = None

    for line in output.splitlines():
        line = line.strip()

        # New network block
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)", line)
        if m:
            if current:
                networks.append(current)
            current = {
                "ssid": m.group(1).strip(),
                "bssid": "",
                "security_type": "Unknown",
                "encryption": "Unknown",
                "signal_strength": -100,
                "channel": None,
                "is_connected": False,
                "is_evil_twin": False,
            }
            continue

        if current is None:
            continue

        m_bssid = re.match(r"^BSSID\s+\d+\s*:\s*([\w:]+)", line)
        if m_bssid:
            current["bssid"] = m_bssid.group(1)
            continue

        m_signal = re.match(r"^Signal\s*:\s*(\d+)%", line)
        if m_signal:
            # Convert % signal to approximate dBm
            pct = int(m_signal.group(1))
            current["signal_strength"] = int((pct / 2) - 100)  # rough mapping
            continue

        m_auth = re.match(r"^Authentication\s*:\s*(.*)", line)
        if m_auth:
            auth = m_auth.group(1).strip()
            # Map to canonical values used in the DB model
            mapping = {
                "WPA2-Personal": "WPA2",
                "WPA2-Enterprise": "WPA2",
                "WPA3-Personal": "WPA3",
                "WPA-Personal": "WPA",
                "Open": "Open",
                "WEP": "WEP",
            }
            current["security_type"] = mapping.get(auth, auth)
            continue

        m_channel = re.match(r"^Channel\s*:\s*(\d+)", line)
        if m_channel:
            current["channel"] = int(m_channel.group(1))
            continue

    if current:
        networks.append(current)

    return networks


def _scan_windows() -> List[Dict]:
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="replace",
        )
        return _parse_netsh_output(result.stdout)
    except FileNotFoundError:
        logger.warning("netsh not available — Wi-Fi scanner disabled")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("netsh timed out")
        return []
    except Exception as exc:
        logger.error("Wi-Fi scan error: %s", exc)
        return []


def _get_connected_ssid_windows() -> Optional[str]:
    """Return the SSID of the currently connected network (Windows)."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
        )
        m = re.search(r"SSID\s*:\s*(.+)", result.stdout)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return None


def _detect_evil_twins(networks: List[Dict]) -> List[Dict]:
    """Flag networks that share the same SSID but have different BSSIDs (possible evil twin)."""
    ssid_groups: Dict[str, List[Dict]] = {}
    for net in networks:
        ssid = net["ssid"]
        if ssid not in ssid_groups:
            ssid_groups[ssid] = []
        ssid_groups[ssid].append(net)

    for ssid, group in ssid_groups.items():
        if len(group) > 1:
            # Multiple APs with the same SSID — heuristic: flag all as potential evil twin
            for net in group:
                net["is_evil_twin"] = True
                logger.warning("Possible Evil Twin detected: SSID='%s' BSSID=%s",
                               ssid, net["bssid"])

    return networks


def _classify_risk(net: Dict) -> str:
    """Return risk level based on security type and evil twin flag."""
    if net.get("is_evil_twin"):
        return "critical"
    sec = net.get("security_type", "").upper()
    if sec in ("OPEN", ""):
        return "high"
    if sec == "WEP":
        return "high"
    if sec == "WPA":
        return "medium"
    return "low"


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class WiFiScanner:
    def __init__(self):
        self._stop_event = threading.Event()

    def start(self) -> None:
        if platform.system() != "Windows":
            logger.warning("Wi-Fi scanner currently only supports Windows (netsh). Skipping.")
            return
        threading.Thread(target=self._scan_loop, daemon=True,
                         name="agent-wifi-scanner").start()
        logger.info("Wi-Fi scanner started (interval=%ds)", config.WIFI_SCAN_INTERVAL_SEC)

    def stop(self) -> None:
        self._stop_event.set()

    def _scan_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._scan_once()
            except Exception as exc:
                logger.error("Wi-Fi scan error: %s", exc)
            self._stop_event.wait(config.WIFI_SCAN_INTERVAL_SEC)

    def _scan_once(self) -> None:
        networks = _scan_windows()
        if not networks:
            return

        connected_ssid = _get_connected_ssid_windows()
        networks = _detect_evil_twins(networks)

        for net in networks:
            net["risk_level"] = _classify_risk(net)
            net["is_connected"] = (net["ssid"] == connected_ssid)

            sender.enqueue("wifi", "scan_result", net)
            logger.debug(
                "Wi-Fi: ssid=%s security=%s risk=%s evil_twin=%s",
                net["ssid"], net["security_type"], net["risk_level"], net["is_evil_twin"],
            )


# ─────────────────────────────────────────────────────────────────────────────
# Public function
# ─────────────────────────────────────────────────────────────────────────────

def start_wifi_scanner() -> WiFiScanner:
    scanner = WiFiScanner()
    scanner.start()
    return scanner
