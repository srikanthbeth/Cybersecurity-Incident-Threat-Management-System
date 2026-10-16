
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from core.config import settings
from core.dependencies import get_current_user
from database import get_db
from models.user import User
from schemas.auth import (
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from services.auth_service import AuthService


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    return AuthService(db).register(
        full_name=payload.full_name,
        email=str(payload.email),
        password=payload.password,
    )


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    return AuthService(db).login(
        email=str(payload.email),
        password=payload.password,
    )


@router.post("/login/form", response_model=TokenResponse)
def login_form(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    return AuthService(db).login(
        email=form.username,
        password=form.password,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(
    payload: RefreshRequest,
    db: Session = Depends(get_db),
):
    return AuthService(db).refresh(payload.refresh_token)


@router.get("/me", response_model=UserResponse)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return current_user


@router.post("/logout", response_model=MessageResponse)
def logout(
    payload: LogoutRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    authorization = request.headers.get("Authorization", "")

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token is required.",
        )

    access_token = authorization[7:]

    AuthService(db).logout(
        access_token=access_token,
        refresh_token=payload.refresh_token,
    )

    return {"message": "Logged out successfully."}


@router.post(
    "/password-reset/request",
    response_model=MessageResponse,
)
def request_password_reset(
    payload: PasswordResetRequest,
    db: Session = Depends(get_db),
):
    reset_token = AuthService(db).request_password_reset(
        str(payload.email)
    )

    response = {
        "message": (
            "If an active account exists for this email, "
            "password reset instructions will be sent."
        )
    }

    # For local development only. Use a secure email delivery
    # mechanism instead of returning this token in production.
    if settings.ENVIRONMENT == "development" and reset_token:
        response["reset_token"] = reset_token

    return response


@router.post(
    "/password-reset/confirm",
    response_model=MessageResponse,
)
def confirm_password_reset(
    payload: PasswordResetConfirm,
    db: Session = Depends(get_db),
):
    AuthService(db).confirm_password_reset(
        token=payload.token,
        new_password=payload.new_password,
    )

    return {"message": "Password has been reset successfully."}
