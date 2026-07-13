#!/usr/bin/env python3
"""Create default users. Safe to re-run — skips existing usernames."""
import os

from dotenv import load_dotenv

load_dotenv()

from app.auth import hash_password
from app.models import Base, SessionLocal, User, UserRole, engine

Base.metadata.create_all(bind=engine)

SEED_USERS = [
    ("admin",    "admin123",    UserRole.admin),
    ("analyst",  "analyst123",  UserRole.analyst),
    ("readonly", "readonly123", UserRole.readonly),
]


def seed():
    db = SessionLocal()
    try:
        for username, password, role in SEED_USERS:
            if db.query(User).filter(User.username == username).first():
                print(f"  skip   {username} (already exists)")
                continue
            db.add(User(
                username=username,
                hashed_password=hash_password(password),
                role=role,
            ))
            print(f"  create {username} ({role.value})")
        db.commit()
        print("Done.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
