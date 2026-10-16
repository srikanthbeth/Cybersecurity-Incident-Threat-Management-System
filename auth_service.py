
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import settings
from core.security import (
    create_token,
    decode_token,
    generate_random_token,
    hash_password,
    hash_token,
    verify_password,
)
from models.auth_token import PasswordResetToken
from models.user import User
from repositories.auth_repository import AuthRepository


PUBLIC_ROLE = "SECURITY_ANALYST"

ALLOWED_ROLES = {
    "SUPER_ADMIN",
    "SECURITY_MANAGER",
    "SECURITY_ANALYST",
    "INCIDENT_RESPONDER",
    "AUDITOR",
    "VIEWER",
}


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = AuthRepository(db)

    def register(
        self,
        full_name: str,
        email: str,
        password: str,
    ) -> User:
        normalized_email = email.strip().lower()

        if self.repo.get_user_by_email(normalized_email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists.",
            )

        user = User(
            full_name=full_name.strip(),
            email=normalized_email,
            password_hash=hash_password(password),
            role=PUBLIC_ROLE,
            is_active=True,
        )
        return self.repo.create_user(user)

    def login(self, email: str, password: str) -> dict:
        user = self.repo.get_user_by_email(email)

        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account is inactive.",
            )

        return self._issue_tokens(user)

    def _issue_tokens(self, user: User) -> dict:
        access_token, _, _ = create_token(
            user_id=user.id,
            role=user.role,
            token_type="access",
            expires_delta=timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            ),
        )

        refresh_token, _, _ = create_token(
            user_id=user.id,
            role=user.role,
            token_type="refresh",
            expires_delta=timedelta(
                days=settings.REFRESH_TOKEN_EXPIRE_DAYS
            ),
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user,
        }

    def refresh(self, refresh_token: str) -> dict:
        try:
            payload = decode_token(refresh_token, "refresh")
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token.",
            )

        user_id = int(payload["sub"])
        jti = payload["jti"]

        if self.repo.is_token_revoked(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has already been used or revoked.",
            )

        user = self.repo.get_user_by_id(user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is unavailable.",
            )

        expires_at = datetime.fromtimestamp(
            payload["exp"],
            tz=timezone.utc,
        )

        self.repo.revoke_token(jti, user.id, expires_at)

        return self._issue_tokens(user)

    def logout(
        self,
        access_token: str,
        refresh_token: str | None = None,
    ) -> None:
        try:
            access_payload = decode_token(access_token, "access")
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid access token.",
            )

        user_id = int(access_payload["sub"])
        tokens_to_revoke = [
            (
                access_payload["jti"],
                datetime.fromtimestamp(
                    access_payload["exp"],
                    tz=timezone.utc,
                ),
            )
        ]

        if refresh_token:
            try:
                refresh_payload = decode_token(refresh_token, "refresh")
                if int(refresh_payload["sub"]) == user_id:
                    tokens_to_revoke.append(
                        (
                            refresh_payload["jti"],
                            datetime.fromtimestamp(
                                refresh_payload["exp"],
                                tz=timezone.utc,
                            ),
                        )
                    )
            except (ValueError, TypeError, KeyError):
                pass

        for jti, expires_at in tokens_to_revoke:
            self.repo.revoke_token(jti, user_id, expires_at)

    def request_password_reset(self, email: str) -> str | None:
        user = self.repo.get_user_by_email(email)

        if not user or not user.is_active:
            return None

        raw_token = generate_random_token()
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(
                    minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES
                )
            ),
            used=False,
        )

        self.db.add(reset_token)
        self.db.commit()

        return raw_token

    def confirm_password_reset(
        self,
        token: str,
        new_password: str,
    ) -> None:
        reset_token = self.repo.get_reset_token(hash_token(token))

        if not reset_token or reset_token.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset token.",
            )

        expires_at = reset_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset token.",
            )

        user = self.repo.get_user_by_id(reset_token.user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset token.",
            )

        user.password_hash = hash_password(new_password)
        reset_token.used = True

        other_tokens = self.db.scalars(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used.is_(False),
            )
        ).all()

        for item in other_tokens:
            item.used = True

        self.db.commit()

    def set_account_active(
        self,
        user_id: int,
        is_active: bool,
    ) -> User:
        user = self.repo.get_user_by_id(user_id)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        if user.role == "SUPER_ADMIN" and not is_active and user.is_active:
            active_admins = self.db.scalars(
                select(User).where(
                    User.role == "SUPER_ADMIN",
                    User.is_active.is_(True),
                )
            ).all()

            if len(active_admins) <= 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cannot deactivate the last active Super Admin.",
                )

        user.is_active = is_active
        self.db.commit()
        self.db.refresh(user)
        return user

    def set_user_role(self, user_id: int, role: str) -> User:
        if role not in ALLOWED_ROLES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid user role.",
            )

        user = self.repo.get_user_by_id(user_id)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        if user.role == "SUPER_ADMIN" and role != "SUPER_ADMIN":
            if user.is_active:
                active_admins = self.db.scalars(
                    select(User).where(
                        User.role == "SUPER_ADMIN",
                        User.is_active.is_(True),
                    )
                ).all()

                if len(active_admins) <= 1:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Cannot demote the last active Super Admin.",
                    )

        user.role = role
        self.db.commit()
        self.db.refresh(user)
        return user
