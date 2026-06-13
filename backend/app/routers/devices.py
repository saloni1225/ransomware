import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models import Device, ThreatEvent
from app.schemas import DeviceCreate, DeviceHeartbeat, DeviceResponse
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/devices", tags=["Devices"])

@router.get("/", response_model=List[DeviceResponse])
def list_devices(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    return db.query(Device).all()

@router.post("/register", response_model=DeviceResponse)
def register_device(device_in: DeviceCreate, db: Session = Depends(get_db)):
    # Check if device exists
    device = db.query(Device).filter(Device.id == device_in.id).first()
    if device:
        # Update details
        device.hostname = device_in.hostname
        device.ip_address = device_in.ip_address
        device.mac_address = device_in.mac_address
        device.os_type = device_in.os_type
        device.firewall_status = device_in.firewall_status
        device.status = "online"
        device.last_seen = datetime.datetime.utcnow()
    else:
        # Create device
        device = Device(
            id=device_in.id,
            hostname=device_in.hostname,
            ip_address=device_in.ip_address,
            mac_address=device_in.mac_address,
            os_type=device_in.os_type,
            firewall_status=device_in.firewall_status,
            status="online",
            trust_score=100,
            last_seen=datetime.datetime.utcnow()
        )
        db.add(device)
    
    db.commit()
    db.refresh(device)
    return device

@router.post("/{device_id}/heartbeat", response_model=DeviceResponse)
def device_heartbeat(device_id: str, heartbeat: DeviceHeartbeat, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    device.status = heartbeat.status
    device.firewall_status = heartbeat.firewall_status
    device.last_seen = datetime.datetime.utcnow()
    
    # Recalculate trust score based on status and active alerts
    # Weight factors:
    # OS Updates: 20%, Firewall: 15%, Wi-Fi: 10%, USB: 10%, Malware Events: 20%, Identity Risk: 15%, Browser: 10%
    base_score = 100
    
    # 1. Firewall deduction
    if heartbeat.firewall_status == "disabled":
        base_score -= 15
        
    # 2. Count active malware/ransomware events on this device
    active_threats_count = (
        db.query(ThreatEvent)
        .filter(
            ThreatEvent.device_id == device_id,
            ThreatEvent.status == "active"
        )
        .count()
    )
    
    # Deduct 15 points per active threat, max 40 points deduction for threats
    base_score -= min(active_threats_count * 15, 40)
    
    if heartbeat.trust_score is not None:
        # Override if agent computed score is sent, but cap it
        device.trust_score = heartbeat.trust_score
    else:
        device.trust_score = max(base_score, 0)
        
    db.commit()
    db.refresh(device)
    return device

@router.get("/{device_id}/trust-breakdown")
def get_trust_breakdown(device_id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
        
    # Standard weighting details:
    # OS Updates: 20%
    # Firewall: 15%
    # Wi-Fi Security: 10%
    # USB Risk: 10%
    # Malware Events: 20%
    # Identity Risk: 15%
    # Browser Risk: 10%
    
    firewall_val = 15 if device.firewall_status == "enabled" else 0
    
    active_threats = db.query(ThreatEvent).filter(ThreatEvent.device_id == device_id, ThreatEvent.status == "active").all()
    
    malware_val = 20
    identity_val = 15
    usb_val = 10
    browser_val = 10
    
    for threat in active_threats:
        if threat.category == "ransomware" or threat.category == "malware":
            malware_val = max(0, malware_val - 10)
        elif threat.category == "identity":
            identity_val = max(0, identity_val - 10)
        elif threat.category == "usb":
            usb_val = max(0, usb_val - 5)
        elif threat.category == "deception":
            identity_val = max(0, identity_val - 5)
            
    # Mocking OS Updates & Wi-Fi score components for display
    os_updates = 20 # Assume 100% updated in Phase 1
    wifi_sec = 10  # Assume 100% secure in Phase 1
    
    calculated = os_updates + firewall_val + wifi_sec + usb_val + malware_val + identity_val + browser_val
    device.trust_score = calculated
    db.commit()
    
    return {
        "device_id": device_id,
        "overall_score": calculated,
        "breakdown": {
            "os_updates": {"score": os_updates, "max": 20, "label": "OS Updates (Latest)"},
            "firewall_status": {"score": firewall_val, "max": 15, "label": f"Firewall status ({device.firewall_status})"},
            "wifi_security": {"score": wifi_sec, "max": 10, "label": "Wi-Fi Security (WPA3)"},
            "usb_risk": {"score": usb_val, "max": 10, "label": "USB Removable Control"},
            "malware_events": {"score": malware_val, "max": 20, "label": "Malware & Ransomware logs"},
            "identity_risk": {"score": identity_val, "max": 15, "label": "Identity & Credential safety"},
            "browser_risk": {"score": browser_val, "max": 10, "label": "Safe Browsing"}
        }
    }

@router.get("/{device_id}/trust-score")
def get_trust_score_v2(device_id: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    """Phase 3: 6-component weighted trust scoring using the trust engine."""
    from app.services.trust_engine import compute_trust_score
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return compute_trust_score(db, device_id)
