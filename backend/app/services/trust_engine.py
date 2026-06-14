"""
Trust Score Engine — 6-component weighted scoring for Device Trust (Phase 3).
Replaces the simple decrement approach from Phase 1 with a rich breakdown.
"""
from sqlalchemy.orm import Session
from app.models import Device, ThreatEvent, MalwareScan, FirewallRule, WiFiNetwork, PrivacyEvent
import datetime

WEIGHT_MALWARE_FREE = 20
WEIGHT_NO_ACTIVE_THREATS = 20
WEIGHT_FIREWALL_ENABLED = 15
WEIGHT_SAFE_WIFI = 10
WEIGHT_NO_PRIVACY_EVENTS = 15
WEIGHT_RECENT_HEARTBEAT = 20

def compute_trust_score(db: Session, device_id: str) -> dict:
    """
    Computes a 6-component trust score for a device.
    Returns dict with component scores, total, and label.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        return {"total": 0, "label": "Unknown", "components": {}}

    scores = {}
    breakdown = {}

    # 1. Malware-free score
    infected = db.query(MalwareScan).filter(
        MalwareScan.device_id == device_id,
        MalwareScan.status.in_(["infected", "suspicious"])
    ).count()
    if infected == 0:
        scores["malware_free"] = WEIGHT_MALWARE_FREE
        breakdown["malware_free"] = {"score": WEIGHT_MALWARE_FREE, "max": WEIGHT_MALWARE_FREE, "status": "pass", "detail": "No malware detected"}
    elif infected <= 2:
        scores["malware_free"] = int(WEIGHT_MALWARE_FREE * 0.5)
        breakdown["malware_free"] = {"score": scores["malware_free"], "max": WEIGHT_MALWARE_FREE, "status": "warn", "detail": f"{infected} suspicious file(s) found"}
    else:
        scores["malware_free"] = 0
        breakdown["malware_free"] = {"score": 0, "max": WEIGHT_MALWARE_FREE, "status": "fail", "detail": f"{infected} malware threats detected"}

    # 2. No active threats score
    active_threats = db.query(ThreatEvent).filter(
        ThreatEvent.device_id == device_id,
        ThreatEvent.status == "active"
    ).count()
    critical_threats = db.query(ThreatEvent).filter(
        ThreatEvent.device_id == device_id,
        ThreatEvent.severity == "critical",
        ThreatEvent.status == "active"
    ).count()
    if active_threats == 0:
        scores["no_active_threats"] = WEIGHT_NO_ACTIVE_THREATS
        breakdown["no_active_threats"] = {"score": WEIGHT_NO_ACTIVE_THREATS, "max": WEIGHT_NO_ACTIVE_THREATS, "status": "pass", "detail": "No active threat events"}
    elif critical_threats > 0:
        scores["no_active_threats"] = 0
        breakdown["no_active_threats"] = {"score": 0, "max": WEIGHT_NO_ACTIVE_THREATS, "status": "fail", "detail": f"{critical_threats} critical alert(s) active"}
    else:
        scores["no_active_threats"] = int(WEIGHT_NO_ACTIVE_THREATS * 0.4)
        breakdown["no_active_threats"] = {"score": scores["no_active_threats"], "max": WEIGHT_NO_ACTIVE_THREATS, "status": "warn", "detail": f"{active_threats} active threat event(s)"}

    # 3. Firewall enabled score
    if device.firewall_status == "enabled":
        scores["firewall_enabled"] = WEIGHT_FIREWALL_ENABLED
        breakdown["firewall_enabled"] = {"score": WEIGHT_FIREWALL_ENABLED, "max": WEIGHT_FIREWALL_ENABLED, "status": "pass", "detail": "Host firewall is active"}
    else:
        scores["firewall_enabled"] = 0
        breakdown["firewall_enabled"] = {"score": 0, "max": WEIGHT_FIREWALL_ENABLED, "status": "fail", "detail": "Firewall is disabled or unknown"}

    # 4. Safe Wi-Fi score
    risky_wifi = db.query(WiFiNetwork).filter(
        WiFiNetwork.device_id == device_id,
        WiFiNetwork.risk_level.in_(["high", "critical"]),
        WiFiNetwork.is_connected == True
    ).count()
    evil_twin = db.query(WiFiNetwork).filter(
        WiFiNetwork.device_id == device_id,
        WiFiNetwork.is_evil_twin == True,
        WiFiNetwork.is_connected == True
    ).count()
    if evil_twin > 0:
        scores["safe_wifi"] = 0
        breakdown["safe_wifi"] = {"score": 0, "max": WEIGHT_SAFE_WIFI, "status": "fail", "detail": "Connected to Evil Twin network"}
    elif risky_wifi > 0:
        scores["safe_wifi"] = int(WEIGHT_SAFE_WIFI * 0.3)
        breakdown["safe_wifi"] = {"score": scores["safe_wifi"], "max": WEIGHT_SAFE_WIFI, "status": "warn", "detail": f"Connected to {risky_wifi} risky network(s)"}
    else:
        scores["safe_wifi"] = WEIGHT_SAFE_WIFI
        breakdown["safe_wifi"] = {"score": WEIGHT_SAFE_WIFI, "max": WEIGHT_SAFE_WIFI, "status": "pass", "detail": "No risky Wi-Fi connections"}

    # 5. No privacy events score
    recent_privacy = db.query(PrivacyEvent).filter(
        PrivacyEvent.device_id == device_id,
        PrivacyEvent.is_blocked == False,
        PrivacyEvent.timestamp >= datetime.datetime.utcnow() - datetime.timedelta(days=7)
    ).count()
    if recent_privacy == 0:
        scores["no_privacy_events"] = WEIGHT_NO_PRIVACY_EVENTS
        breakdown["no_privacy_events"] = {"score": WEIGHT_NO_PRIVACY_EVENTS, "max": WEIGHT_NO_PRIVACY_EVENTS, "status": "pass", "detail": "No privacy violations in last 7 days"}
    elif recent_privacy <= 2:
        scores["no_privacy_events"] = int(WEIGHT_NO_PRIVACY_EVENTS * 0.5)
        breakdown["no_privacy_events"] = {"score": scores["no_privacy_events"], "max": WEIGHT_NO_PRIVACY_EVENTS, "status": "warn", "detail": f"{recent_privacy} privacy event(s) recently"}
    else:
        scores["no_privacy_events"] = 0
        breakdown["no_privacy_events"] = {"score": 0, "max": WEIGHT_NO_PRIVACY_EVENTS, "status": "fail", "detail": f"{recent_privacy} unblocked privacy events"}

    # 6. Recent heartbeat score
    if device.last_seen:
        minutes_since = (datetime.datetime.utcnow() - device.last_seen).total_seconds() / 60
        if minutes_since <= 5:
            scores["recent_heartbeat"] = WEIGHT_RECENT_HEARTBEAT
            breakdown["recent_heartbeat"] = {"score": WEIGHT_RECENT_HEARTBEAT, "max": WEIGHT_RECENT_HEARTBEAT, "status": "pass", "detail": f"Last seen {int(minutes_since)}m ago"}
        elif minutes_since <= 30:
            scores["recent_heartbeat"] = int(WEIGHT_RECENT_HEARTBEAT * 0.6)
            breakdown["recent_heartbeat"] = {"score": scores["recent_heartbeat"], "max": WEIGHT_RECENT_HEARTBEAT, "status": "warn", "detail": f"Last seen {int(minutes_since)}m ago"}
        else:
            scores["recent_heartbeat"] = 0
            breakdown["recent_heartbeat"] = {"score": 0, "max": WEIGHT_RECENT_HEARTBEAT, "status": "fail", "detail": f"Offline for {int(minutes_since // 60)}h {int(minutes_since % 60)}m"}
    else:
        scores["recent_heartbeat"] = 0
        breakdown["recent_heartbeat"] = {"score": 0, "max": WEIGHT_RECENT_HEARTBEAT, "status": "fail", "detail": "Device never reported"}

    total = sum(scores.values())

    # Update device's trust_score in DB
    device.trust_score = total
    db.commit()

    if total >= 85:
        label = "Trusted"
    elif total >= 60:
        label = "Moderate Risk"
    elif total >= 40:
        label = "At Risk"
    else:
        label = "Untrusted"

    return {
        "device_id": device_id,
        "total": total,
        "max": 100,
        "label": label,
        "components": breakdown,
    }
