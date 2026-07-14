#!/usr/bin/env python3
"""Create demo users, customers, signatures, and detections. Safe to re-run — skips what already exists."""
import os

from dotenv import load_dotenv

load_dotenv()

from app.auth import hash_password
from app.models import (
    Base,
    Customer,
    Detection,
    DetectionStatus,
    SessionLocal,
    Signature,
    User,
    UserRole,
    engine,
)

Base.metadata.create_all(bind=engine)

SEED_USERS = [
    ("admin",    "admin123",    UserRole.admin),
    ("analyst",  "analyst123",  UserRole.analyst),
    ("readonly", "readonly123", UserRole.readonly),
]

SEED_CUSTOMERS = [
    ("Acme Corp",   10),
    ("GlobalBank",  8),
    ("TechStartup", 4),
]

SEED_SIGNATURES = [
    ("SSH Brute Force",  8,  {"event_type": "auth_failure", "protocol": "ssh"}),
    ("Malware Detected", 10, {"event_type": "malware", "severity": "high"}),
    ("Port Scan",        5,  {"event_type": "recon", "protocol": "tcp"}),
]

# (customer name, signature name) pairs to seed as open detections
SEED_DETECTIONS = [
    ("GlobalBank", "SSH Brute Force"),
    ("Acme Corp",  "Malware Detected"),
]


def seed_users(db):
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


def seed_customers(db):
    for name, importance_level in SEED_CUSTOMERS:
        if db.query(Customer).filter(Customer.name == name).first():
            print(f"  skip   {name} (already exists)")
            continue
        db.add(Customer(name=name, importance_level=importance_level))
        print(f"  create {name} (importance {importance_level})")
    db.commit()


def seed_signatures(db):
    for name, priority, fields in SEED_SIGNATURES:
        if db.query(Signature).filter(Signature.name == name).first():
            print(f"  skip   {name} (already exists)")
            continue
        db.add(Signature(name=name, priority=priority, fields=fields))
        print(f"  create {name} (priority {priority})")
    db.commit()


def seed_detections(db):
    if db.query(Detection).filter(Detection.status == DetectionStatus.open).first():
        print("  skip   open detections already exist")
        return

    for customer_name, signature_name in SEED_DETECTIONS:
        customer = db.query(Customer).filter(Customer.name == customer_name).first()
        signature = db.query(Signature).filter(Signature.name == signature_name).first()
        priority = customer.importance_level * signature.priority
        db.add(Detection(
            signature_id=signature.id,
            customer_id=customer.id,
            priority=priority,
            status=DetectionStatus.open,
        ))
        print(f"  create {customer_name} / {signature_name} (priority {priority})")
    db.commit()


def seed():
    db = SessionLocal()
    try:
        print("Users:")
        seed_users(db)
        print("Customers:")
        seed_customers(db)
        print("Signatures:")
        seed_signatures(db)
        print("Detections:")
        seed_detections(db)
        print("Done.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
