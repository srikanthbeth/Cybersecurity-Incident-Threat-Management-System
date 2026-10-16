
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from models.user import User
from schemas.user import UserProfileUpdate


class UserManagementService:
    def __init__(self, db: Session):
        self.db = db

    def list_users(
        self,
        search: str | None = None,
        role: str | None = None,
        active: bool | None = None,
        page: int = 1,
        page_size: int = 20,
    ):
        query = select(User)

        if search:
            term = f"%{search.strip()}%"
            query = query.where(
                User.full_name.ilike(term) | User.email.ilike(term)
            )

        if role:
            query = query.where(User.role == role)

        if active is not None:
            query = query.where(User.is_active.is_(active))

        query = query.order_by(User.id).offset((page - 1) * page_size)
        query = query.limit(page_size)
        return list(self.db.scalars(query).all())

    def get_user(self, user_id: int):
        user = self.db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        return user

    def update_profile(
        self,
        user_id: int,
        payload: UserProfileUpdate,
    ):
        user = self.get_user(user_id)
        user.full_name = payload.full_name.strip()

        if len(user.full_name) < 2:
            raise HTTPException(
                status_code=422,
                detail="Full name must contain at least 2 characters.",
            )

        self.db.commit()
        self.db.refresh(user)
        return user
