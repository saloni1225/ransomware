import pytest
from fastapi.testclient import TestClient
import pyotp
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models import User

# Setup Test Database
Base.metadata.create_all(bind=engine)

@pytest.fixture
def client():
    # Use standard test client
    with TestClient(app) as c:
        yield c

@pytest.fixture(autouse=True)
def clean_db():
    db = SessionLocal()
    try:
        db.query(User).filter(User.email == "test@defense.com").delete()
        db.commit()
    finally:
        db.close()

def test_auth_full_flow(client):
    email = "test@defense.com"
    password = "SecretPassword123"
    
    # 1. Register User
    reg_response = client.post("/api/auth/register", json={
        "email": email,
        "password": password
    })
    if reg_response.status_code != 201:
        print("Registration Error response:", reg_response.json())
    assert reg_response.status_code == 201
    reg_data = reg_response.json()
    assert reg_data["email"] == email
    
    # 2. Login User
    login_response = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert login_data["detail"] == "MFA required"
    assert "qr_code" in login_data
    assert "totp_secret" in login_data
    assert login_data["totp_enabled"] is False
    
    secret = login_data["totp_secret"]
    
    # 3. Generate Valid TOTP Code using pyotp
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    
    # 4. Verify TOTP Code
    verify_response = client.post("/api/auth/verify-otp", json={
        "email": email,
        "otp_code": valid_code
    })
    assert verify_response.status_code == 200
    verify_data = verify_response.json()
    assert "access_token" in verify_data
    assert verify_data["email"] == email
    
    # 5. Retrieve Profile with Access Token
    headers = {"Authorization": f"Bearer {verify_data['access_token']}"}
    me_response = client.get("/api/auth/me", headers=headers)
    assert me_response.status_code == 200
    me_data = me_response.json()
    assert me_data["email"] == email
