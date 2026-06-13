import datetime
from app.database import engine, SessionLocal, Base
from app.models import User, Device, ThreatLog, ThreatEvent, AIExplanation, AttackStoryline
from app.services.auth_service import hash_password
from app.services.ai_service import generate_ai_explanation
from app.services.correlation_engine import generate_attack_storyline

def seed_db():
    # Recreate tables
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        print("Seeding database...")
        
        # 1. Create Default Admin User
        admin = User(
            email="admin@defense.com",
            hashed_password=hash_password("password123"),
            role="admin",
            totp_secret="JBSWY3DPEHPK3PXP",
            totp_enabled=False
        )
        db.add(admin)
        db.commit()
        print("Created default user: admin@defense.com / password123")
        
        # 2. Create Mock Devices
        dev1 = Device(
            id="win10-office-pc",
            hostname="win10-office-pc",
            ip_address="192.168.1.45",
            mac_address="00:1A:2B:3C:4D:5E",
            os_type="Windows",
            status="online",
            trust_score=75,
            firewall_status="enabled",
            last_seen=datetime.datetime.utcnow()
        )
        dev2 = Device(
            id="macbook-m2-dev",
            hostname="macbook-m2-dev",
            ip_address="192.168.1.112",
            mac_address="F0:18:98:C3:A2:10",
            os_type="macOS",
            status="online",
            trust_score=100,
            firewall_status="enabled",
            last_seen=datetime.datetime.utcnow()
        )
        dev3 = Device(
            id="linux-prod-db",
            hostname="linux-prod-db",
            ip_address="10.0.4.12",
            mac_address="52:54:00:12:34:56",
            os_type="Linux",
            status="offline",
            trust_score=85,
            firewall_status="disabled",
            last_seen=datetime.datetime.utcnow() - datetime.timedelta(hours=2)
        )
        
        db.add_all([dev1, dev2, dev3])
        db.commit()
        print("Created mock devices.")
        
        # 3. Create Threat logs
        log1 = ThreatLog(
            device_id="win10-office-pc",
            type="process",
            action="started",
            details={"name": "outlook.exe", "pid": 4200, "command": "outlook.exe"},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        )
        log2 = ThreatLog(
            device_id="win10-office-pc",
            type="file",
            action="modified",
            details={"path": "C:\\Users\\User\\Downloads\\invoice.pdf.exe", "size": 154000},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=8)
        )
        log3 = ThreatLog(
            device_id="win10-office-pc",
            type="file",
            action="modified",
            details={"modified_count": 42, "entropy": 7.8, "extension": ".locked"},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        )
        log4 = ThreatLog(
            device_id="macbook-m2-dev",
            type="file",
            action="accessed",
            details={"path": "/Users/dev/Documents/salary.xlsx", "process": "scanner.exe"},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
        )
        log5 = ThreatLog(
            device_id="win10-office-pc",
            type="usb",
            action="mounted",
            details={"label": "RecoveryKey", "serial": "USB1238912", "authorized": False},
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
        )
        
        db.add_all([log1, log2, log3, log4, log5])
        db.commit()
        print("Created threat logs.")
        
        # 4. Create Threat Events
        # Ransomware Event
        event1 = ThreatEvent(
            device_id="win10-office-pc",
            title="Ransomware Behavior Detected",
            description="Rapid modification of 42 files. Detected high entropy write buffers.",
            category="ransomware",
            severity="critical",
            status="active",
            confidence_score=94,
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        )
        
        # Deception Honey File Event
        event2 = ThreatEvent(
            device_id="macbook-m2-dev",
            title="Decoy Honey File Access",
            description="Decoy sensitive asset accessed: /Users/dev/Documents/salary.xlsx",
            category="deception",
            severity="high",
            status="quarantined",
            confidence_score=98,
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
        )
        
        # Unauthorized USB Event
        event3 = ThreatEvent(
            device_id="win10-office-pc",
            title="Unauthorized USB Connected",
            description="Blocked connection of unauthorized mass storage: RecoveryKey",
            category="usb",
            severity="medium",
            status="resolved",
            confidence_score=85,
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=2)
        )
        
        db.add_all([event1, event2, event3])
        db.commit()
        print("Created threat events.")
        
        # 5. Generate AI Explanations and Attack Storylines
        for ev in [event1, event2, event3]:
            generate_ai_explanation(db, ev)
            generate_attack_storyline(db, ev)
            
        print("Generated AI Explanations & Attack Storylines successfully.")
        print("Database seeding completed.")
        
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    seed_db()
