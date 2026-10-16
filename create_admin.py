
from getpass import getpass

from sqlalchemy import select

from core.security import hash_password
from database import Base, SessionLocal, engine
import models
from models.user import User


def main():
    Base.metadata.create_all(bind=engine)

    name = input("Super Admin full name: ").strip()
    email = input("Super Admin email: ").strip().lower()
    password = getpass("Password (minimum 12 characters): ")
    confirm_password = getpass("Confirm password: ")

    if len(name) < 2:
        print("Full name must contain at least 2 characters.")
        return

    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    if password != confirm_password:
        print("Passwords do not match.")
        return

    with SessionLocal() as db:
        existing_admin = db.scalar(
            select(User).where(User.role == "SUPER_ADMIN")
        )
        if existing_admin:
            print("A Super Admin already exists.")
            return

        existing_user = db.scalar(
            select(User).where(User.email == email)
        )
        if existing_user:
            print("An account with this email already exists.")
            return

        user = User(
            full_name=name,
            email=email,
            password_hash=hash_password(password),
            role="SUPER_ADMIN",
            is_active=True,
        )
        db.add(user)
        db.commit()

    print("Super Admin created successfully.")


if __name__ == "__main__":
    main()
