import enum
import os
from datetime import datetime
from typing import List, Optional

from dotenv import load_dotenv
from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
    func,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

# reads .env file, connects to PostgresSQL, creates a session factory
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    readonly = "readonly"


class DetectionStatus(str, enum.Enum):
    open = "open"
    active = "active"
    closed = "closed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), nullable=False, default=UserRole.readonly
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    assigned_detections: Mapped[List["Detection"]] = relationship(
        "Detection", back_populates="assignee", foreign_keys="Detection.assigned_to"
    )


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    importance_level: Mapped[int] = mapped_column(Integer, nullable=False)  # 1–10
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    detections: Mapped[List["Detection"]] = relationship(
        "Detection", back_populates="customer"
    )


class Signature(Base):
    __tablename__ = "signatures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    fields: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    detections: Mapped[List["Detection"]] = relationship(
        "Detection", back_populates="signature"
    )


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    signature_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("signatures.id"), nullable=False
    )
    customer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("customers.id"), nullable=False
    )
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[DetectionStatus] = mapped_column(
        Enum(DetectionStatus), nullable=False, default=DetectionStatus.open
    )
    assigned_to: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    signature: Mapped["Signature"] = relationship("Signature", back_populates="detections")
    customer: Mapped["Customer"] = relationship("Customer", back_populates="detections")
    assignee: Mapped[Optional["User"]] = relationship(
        "User", back_populates="assigned_detections", foreign_keys=[assigned_to]
    )

    __table_args__ = (
        Index("ix_detections_status", "status"),
        Index("ix_detections_priority", "priority"),
    )


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
