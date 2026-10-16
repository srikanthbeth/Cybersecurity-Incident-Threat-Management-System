
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from jose import JWTError, jwt
from pwdlib import PasswordHash

from core.config import settings


password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_random_token() -> str:
    return secrets.token_urlsafe(32)


def create_token(
    user_id: int,
    role: str,
    token_type: str,
    expires_delta: timedelta,
) -> tuple[str, str, datetime]:
    if token_type not in {"access", "refresh"}:
        raise ValueError("Invalid token type.")

    now = datetime.now(timezone.utc)
    expires_at = now + expires_delta
    jti = str(uuid4())

    payload = {
        "sub": str(user_id),
        "role": role,
        "type": token_type,
        "jti": jti,
        "iat": now,
        "exp": expires_at,
    }

    encoded_token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )

    return encoded_token, jti, expires_at


def decode_token(
    token: str,
    expected_type: str | None = None,
) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )

        if not payload.get("sub") or not payload.get("jti"):
            raise ValueError("Required token claims are missing.")

        actual_type = payload.get("type")

        if actual_type not in {"access", "refresh"}:
            raise ValueError("Invalid token type.")

        if (
            expected_type is not None
            and actual_type != expected_type
        ):
            raise ValueError("Unexpected token type.")

        return payload

    except (JWTError, ValueError) as exc:
        raise ValueError("Invalid or expired token.") from exc
