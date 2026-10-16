
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from core.dependencies import get_current_user, require_roles
from database import get_db
from models.user import User
from schemas.auth import AccountStatusRequest, RoleUpdateRequest, UserResponse
from schemas.user import ManagedUserResponse, UserProfileUpdate
from services.auth_service import AuthService
from services.user_management_service import UserManagementService


router = APIRouter(prefix="/api/v1/users", tags=["User Management"])


@router.get("", response_model=list[ManagedUserResponse])
def list_users(
    search: str | None = Query(default=None, max_length=120),
    role: str | None = Query(default=None, max_length=40),
    active: bool | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "SECURITY_MANAGER")
    ),
):
    return UserManagementService(db).list_users(
        search=search,
        role=role,
        active=active,
        page=page,
        page_size=page_size,
    )


@router.get("/me", response_model=ManagedUserResponse)
def get_my_profile(
    current_user: User = Depends(get_current_user),
):
    return current_user


@router.patch("/me/profile", response_model=ManagedUserResponse)
def update_my_profile(
    payload: UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return UserManagementService(db).update_profile(current_user.id, payload)


@router.get("/{user_id}", response_model=ManagedUserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "SECURITY_MANAGER")
    ),
):
    return UserManagementService(db).get_user(user_id)


@router.patch("/{user_id}/profile", response_model=ManagedUserResponse)
def update_user_profile(
    user_id: int,
    payload: UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "SECURITY_MANAGER")
    ),
):
    return UserManagementService(db).update_profile(user_id, payload)


@router.patch("/{user_id}/status", response_model=UserResponse)
def update_user_status(
    user_id: int,
    payload: AccountStatusRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("SUPER_ADMIN")),
):
    return AuthService(db).set_account_active(
        user_id=user_id,
        is_active=payload.is_active,
    )


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    payload: RoleUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("SUPER_ADMIN")),
):
    return AuthService(db).set_user_role(
        user_id=user_id,
        role=payload.role,
    )
