from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.routers import auth, devices, threats, reports, malware, network, wifi, firewall, deception, privacy
from app.config import settings

# Create database tables automatically (including new Phase 2 & 3 tables)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Ransomware Defense System API",
    description="Backend services for real-time endpoint threat monitoring, deception engines, and explainable AI.",
    version="2.0.0"
)

# Configure CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for dev ease
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Phase 1 Routers
app.include_router(auth.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(threats.router, prefix="/api")
app.include_router(reports.router, prefix="/api")

# Phase 2 Routers
app.include_router(malware.router, prefix="/api")
app.include_router(network.router, prefix="/api")
app.include_router(wifi.router, prefix="/api")
app.include_router(firewall.router, prefix="/api")

# Phase 3 Routers
app.include_router(deception.router, prefix="/api")
app.include_router(privacy.router, prefix="/api")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "Ransomware Defense System API",
        "version": "2.0.0",
        "phases": ["Phase 1: Core", "Phase 2: Network & Malware", "Phase 3: Deception & Privacy"],
        "documentation": "/docs"
    }
