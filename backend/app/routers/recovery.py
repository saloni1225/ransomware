"""
Recovery & Rollback Center — /api/recovery
==========================================
Provides endpoints to:
- List quarantined files awaiting recovery decisions
- Restore a quarantined file (mark as restored)
- Permanently delete a quarantined file
- View the full recovery action history with pagination
- Rollback a threat event status to 'resolved'
"""

import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import MalwareScan, RecoveryAction, ThreatEvent
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/recovery", tags=["Recovery"])


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas (inline, no need to pollute schemas.py)
# ─────────────────────────────────────────────────────────────────────────────

class RecoveryActionResponse(BaseModel):
    id: int
    scan_id: Optional[int]
    threat_event_id: Optional[int]
    device_id: Optional[str]
    action_type: str
    file_path: Optional[str]
    performed_by: Optional[str]
    status: str
    notes: Optional[str]
    timestamp: datetime.datetime

    class Config:
        from_attributes = True


class QuarantinedFileResponse(BaseModel):
    id: int
    device_id: str
    file_path: str
    file_hash: Optional[str]
    file_size: Optional[int]
    threat_name: Optional[str]
    scan_engine: str
    scan_time: datetime.datetime
    status: str

    class Config:
        from_attributes = True


class RestoreRequest(BaseModel):
    notes: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/quarantine", response_model=List[QuarantinedFileResponse])
def list_quarantined_files(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Return all malware scan records with status 'quarantined'.
    These are files awaiting a restore or delete decision.
    """
    scans = (
        db.query(MalwareScan)
        .filter(MalwareScan.status == "quarantined")
        .order_by(MalwareScan.scan_time.desc())
        .all()
    )
    return scans


@router.post("/restore/{scan_id}", response_model=RecoveryActionResponse)
def restore_file(
    scan_id: int,
    body: RestoreRequest = RestoreRequest(),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Mark a quarantined file as restored and log the recovery action.
    In a real deployment this would also move the file from the quarantine vault.
    """
    scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
    if scan.status != "quarantined":
        raise HTTPException(
            status_code=400,
            detail=f"File is not quarantined (current status: {scan.status}). Cannot restore."
        )

    # Update scan status back to clean
    scan.status = "restored"
    db.commit()

    # Log the recovery action
    action = RecoveryAction(
        scan_id=scan_id,
        device_id=scan.device_id,
        action_type="restore",
        file_path=scan.file_path,
        performed_by=current_user.email,
        status="success",
        notes=body.notes or f"File restored by {current_user.email}",
        timestamp=datetime.datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


@router.post("/delete/{scan_id}", response_model=RecoveryActionResponse)
def delete_permanently(
    scan_id: int,
    body: RestoreRequest = RestoreRequest(),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Permanently mark a quarantined file as deleted."""
    scan = db.query(MalwareScan).filter(MalwareScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found")
    if scan.status not in ("quarantined", "infected", "suspicious"):
        raise HTTPException(status_code=400, detail="File is not in a deletable state")

    scan.status = "deleted"
    db.commit()

    action = RecoveryAction(
        scan_id=scan_id,
        device_id=scan.device_id,
        action_type="delete_permanent",
        file_path=scan.file_path,
        performed_by=current_user.email,
        status="success",
        notes=body.notes or f"File permanently deleted by {current_user.email}",
        timestamp=datetime.datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


@router.post("/rollback/{event_id}", response_model=RecoveryActionResponse)
def rollback_threat_event(
    event_id: int,
    body: RestoreRequest = RestoreRequest(),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Roll back a threat event: mark it as 'resolved' and record the action.
    Useful for false-positive remediation.
    """
    event = db.query(ThreatEvent).filter(ThreatEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")

    previous_status = event.status
    event.status = "resolved"
    db.commit()

    action = RecoveryAction(
        threat_event_id=event_id,
        device_id=event.device_id,
        action_type="rollback",
        performed_by=current_user.email,
        status="success",
        notes=body.notes or f"Event rolled back from '{previous_status}' by {current_user.email}",
        timestamp=datetime.datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


@router.get("/history", response_model=List[RecoveryActionResponse])
def get_recovery_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Return paginated recovery action history (most recent first).
    """
    actions = (
        db.query(RecoveryAction)
        .order_by(RecoveryAction.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return actions


@router.get("/stats")
def get_recovery_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Aggregate recovery statistics for the dashboard widget."""
    total_quarantined = db.query(MalwareScan).filter(MalwareScan.status == "quarantined").count()
    total_restored = db.query(MalwareScan).filter(MalwareScan.status == "restored").count()
    total_deleted = db.query(MalwareScan).filter(MalwareScan.status == "deleted").count()
    total_actions = db.query(RecoveryAction).count()

    recent_actions = (
        db.query(RecoveryAction)
        .order_by(RecoveryAction.timestamp.desc())
        .limit(5)
        .all()
    )

    return {
        "quarantined_files": total_quarantined,
        "restored_files": total_restored,
        "deleted_files": total_deleted,
        "total_actions": total_actions,
        "recent_actions": [
            {
                "id": a.id,
                "action_type": a.action_type,
                "file_path": a.file_path,
                "performed_by": a.performed_by,
                "status": a.status,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in recent_actions
        ],
    }
