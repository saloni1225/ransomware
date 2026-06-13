import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="admin")
    is_active = Column(Boolean, default=True)
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, index=True) # Usually hostname or mac_address
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    os_type = Column(String, nullable=True) # Windows, Linux, macOS
    status = Column(String, default="online") # online, offline
    trust_score = Column(Integer, default=100)
    firewall_status = Column(String, default="enabled") # enabled, disabled, unknown
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)

    logs = relationship("ThreatLog", back_populates="device", cascade="all, delete-orphan")
    threat_events = relationship("ThreatEvent", back_populates="device", cascade="all, delete-orphan")

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    type = Column(String, nullable=False) # file, process, usb, network
    action = Column(String, nullable=False) # e.g. modified, started, mounted, blocked
    details = Column(JSON, nullable=True) # Store specific activity details

    device = relationship("Device", back_populates="logs")

class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    category = Column(String, nullable=False) # ransomware, malware, usb, deception, identity
    text_content = Column(String, nullable=True) # Backwards compatibility/detail
    severity = Column(String, nullable=False) # low, medium, high, critical
    status = Column(String, default="active") # active, quarantined, ignored, resolved
    confidence_score = Column(Integer, default=50)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="threat_events")
    explanations = relationship("AIExplanation", back_populates="threat_event", cascade="all, delete-orphan")
    storylines = relationship("AttackStoryline", back_populates="threat_event", cascade="all, delete-orphan")

class AIExplanation(Base):
    __tablename__ = "ai_explanations"

    id = Column(Integer, primary_key=True, index=True)
    threat_event_id = Column(Integer, ForeignKey("threat_events.id"), nullable=False)
    reasons = Column(JSON, nullable=False) # JSON array of strings
    confidence = Column(Integer, nullable=False)
    recommended_action = Column(String, nullable=False)

    threat_event = relationship("ThreatEvent", back_populates="explanations")

class AttackStoryline(Base):
    __tablename__ = "attack_storylines"

    id = Column(Integer, primary_key=True, index=True)
    threat_event_id = Column(Integer, ForeignKey("threat_events.id"), nullable=False)
    storyline_data = Column(JSON, nullable=False) # JSON structured representation of process/attack chain

    threat_event = relationship("ThreatEvent", back_populates="storylines")
