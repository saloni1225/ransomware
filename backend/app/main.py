from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.routers import auth, devices, threats, reports
from app.config import settings

# Create database tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Ransomware Defense System API",
    description="Backend services for real-time endpoint threat monitoring, deception engines, and explainable AI.",
    version="1.0.0"
)

# Configure CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for dev ease
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(threats.router, prefix="/api")
app.include_router(reports.router, prefix="/api")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "Ransomware Defense System API",
        "documentation": "/docs"
    }
