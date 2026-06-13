from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Device, ThreatEvent, ThreatLog
from app.schemas import DashboardSummary
from app.services.auth_service import get_current_user, get_current_user_optional_query
import datetime

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    total_devices = db.query(Device).count()
    active_devices = db.query(Device).filter(Device.status == "online").count()
    
    critical_threats = (
        db.query(ThreatEvent)
        .filter(ThreatEvent.status == "active", ThreatEvent.severity == "critical")
        .count()
    )
    
    total_threats = db.query(ThreatEvent).filter(ThreatEvent.status == "active").count()
    
    # Calculate average trust score
    devices = db.query(Device).all()
    overall_trust_score = 100
    if devices:
        overall_trust_score = int(sum(d.trust_score for d in devices) / len(devices))
        
    recent_events = (
        db.query(ThreatEvent)
        .order_by(ThreatEvent.id.desc())
        .limit(5)
        .all()
    )
    
    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "critical_threats": critical_threats,
        "total_threats": total_threats,
        "overall_trust_score": overall_trust_score,
        "recent_events": recent_events
    }

@router.get("/export-html", response_class=HTMLResponse)
def export_report_html(db: Session = Depends(get_db), current_user = Depends(get_current_user_optional_query)):
    # Fetch details to build a gorgeous printable executive report
    total_devices = db.query(Device).count()
    active_devices = db.query(Device).filter(Device.status == "online").count()
    total_threats = db.query(ThreatEvent).count()
    critical_threats = db.query(ThreatEvent).filter(ThreatEvent.severity == "critical").count()
    devices = db.query(Device).all()
    avg_trust = int(sum(d.trust_score for d in devices) / len(devices)) if devices else 100
    
    all_threats = db.query(ThreatEvent).order_by(ThreatEvent.timestamp.desc()).all()
    
    threats_rows = ""
    for t in all_threats:
        status_color = "red" if t.status == "active" else "green"
        threats_rows += f"""
        <tr>
            <td>{t.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
            <td>{t.device_id}</td>
            <td>{t.title}</td>
            <td><span style="text-transform:uppercase; font-weight:bold;">{t.category}</span></td>
            <td><span style="color:{status_color}; font-weight:bold;">{t.status}</span></td>
            <td>{t.severity.upper()}</td>
            <td>{t.confidence_score}%</td>
        </tr>
        """
        
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Ransomware Defense System - Executive Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                color: #333;
                background-color: #fff;
                margin: 40px;
                line-height: 1.6;
            }}
            .header {{
                border-bottom: 3px solid #1a365d;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }}
            .title {{
                color: #1a365d;
                margin: 0;
                font-size: 28px;
                font-weight: 700;
            }}
            .subtitle {{
                color: #718096;
                margin: 5px 0 0 0;
                font-size: 14px;
            }}
            .meta-grid {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 20px;
                margin-bottom: 40px;
            }}
            .meta-card {{
                background-color: #f7fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 20px;
                text-align: center;
            }}
            .meta-card h3 {{
                margin: 0 0 10px 0;
                color: #4a5568;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            .meta-card .value {{
                font-size: 28px;
                font-weight: 700;
                color: #2b6cb0;
                margin: 0;
            }}
            .meta-card .value.critical {{
                color: #c53030;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #e2e8f0;
            }}
            th {{
                background-color: #2b6cb0;
                color: #fff;
                font-weight: 600;
            }}
            tr:nth-child(even) {{
                background-color: #f8fafc;
            }}
            .footer {{
                margin-top: 50px;
                border-top: 1px solid #e2e8f0;
                padding-top: 20px;
                font-size: 12px;
                color: #a0aec0;
                text-align: center;
            }}
            @media print {{
                body {{ margin: 0; }}
                .no-print {{ display: none; }}
            }}
            .print-btn {{
                background-color: #2b6cb0;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                border-radius: 5px;
                cursor: pointer;
                float: right;
                margin-bottom: 20px;
            }}
        </style>
    </head>
    <body>
        <button class="print-btn no-print" onclick="window.print()">Print/Save PDF</button>
        <div class="header">
            <h1 class="title">Ransomware Defense System</h1>
            <p class="subtitle">Executive Status & Threat Incident Report • Generated on {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        </div>
        
        <div class="meta-grid">
            <div class="meta-card">
                <h3>System Status Score</h3>
                <p class="value">{avg_trust}/100</p>
            </div>
            <div class="meta-card">
                <h3>Protected Devices</h3>
                <p class="value">{total_devices} ({active_devices} Online)</p>
            </div>
            <div class="meta-card">
                <h3>Total Incident Reports</h3>
                <p class="value">{total_threats}</p>
            </div>
            <div class="meta-card">
                <h3>Critical Security Alerts</h3>
                <p class="value critical">{critical_threats}</p>
            </div>
        </div>

        <h2>Security Threat Events & History</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Device Hostname</th>
                    <th>Threat Incident</th>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {threats_rows}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Confidential Internal Report • Ransomware Defense System Endpoint Monitoring</p>
        </div>
    </body>
    </html>
    """
    return html_content
