
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.auth_token import PasswordResetToken, RevokedToken
from models.user import User


class AuthRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_user_by_email(self, email: str) -> User | None:
        return self.db.scalar(
            select(User).where(User.email == email.strip().lower())
        )

    def get_user_by_id(self, user_id: int) -> User | None:
        return self.db.get(User, user_id)

    def create_user(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def is_token_revoked(self, jti: str) -> bool:
        return self.db.get(RevokedToken, jti) is not None

    def revoke_token(
        self,
        jti: str,
        user_id: int,
        expires_at,
    ) -> None:
        if not self.is_token_revoked(jti):
            self.db.add(
                RevokedToken(
                    jti=jti,
                    user_id=user_id,
                    expires_at=expires_at,
                )
            )
            self.db.commit()

    def get_reset_token(
        self,
        token_hash: str,
    ) -> PasswordResetToken | None:
        return self.db.scalar(
            select(PasswordResetToken).where(
                PasswordResetToken.token_hash == token_hash
            )
        )

    def invalidate_reset_tokens(self, user_id: int) -> None:
        tokens = self.db.scalars(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.used.is_(False),
            )
        ).all()

        for token in tokens:
            token.used = True

        self.db.commit()
