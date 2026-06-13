from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserLogin, UserResponse, OTPVerify, Token
from app.services.auth_service import (
    hash_password, verify_password, generate_totp_secret,
    get_totp_uri, generate_qr_code_base64, verify_totp,
    create_access_token, get_current_user
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    # Check if user email already exists
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user with a unique TOTP secret
    db_user = User(
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role="admin",
        totp_secret=generate_totp_secret(),
        totp_enabled=False
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.post("/login")
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    # Retrieve user
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    
    # Lazy initialize TOTP secret if not present
    if not user.totp_secret:
        user.totp_secret = generate_totp_secret()
        db.commit()
        db.refresh(user)
        
    # Generate QR Code details
    uri = get_totp_uri(user.totp_secret, user.email)
    qr_code_base64 = generate_qr_code_base64(uri)
    
    return {
        "detail": "MFA required",
        "qr_code": qr_code_base64,
        "totp_secret": user.totp_secret,
        "totp_enabled": user.totp_enabled,
        "email": user.email
    }

@router.post("/verify-otp", response_model=Token)
def verify_otp_endpoint(payload: OTPVerify, db: Session = Depends(get_db)):
    # Validate user exists
    user = db.query(User).filter(User.email == payload.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found"
        )
    
    # Verify TOTP code
    is_valid = verify_totp(user.totp_secret, payload.otp_code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired MFA code"
        )
    
    # Activate TOTP
    if not user.totp_enabled:
        user.totp_enabled = True
        db.commit()
    
    # Generate JWT Token
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "email": user.email,
        "role": user.role
    }

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/debug-totp")
def get_debug_totp(email: str, db: Session = Depends(get_db)):
    if settings.ENVIRONMENT != "development":
        raise HTTPException(status_code=403, detail="Forbidden in non-dev environments")
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=404, detail="User or TOTP secret not found")
    import pyotp
    totp = pyotp.TOTP(user.totp_secret)
    return {"code": totp.now()}
