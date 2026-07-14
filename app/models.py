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

# sets up the database connection every route in the app will use
load_dotenv()

# falls back to a local SQLite file so the app (and CI) can still start
# without a real Postgres URL configured
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

engine = create_engine(DATABASE_URL)
# turned off so it doesn't interfere with the row-locking used when an analyst claims a detection
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


# the roles that control what a user can see and do in the app
class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    readonly = "readonly"


# where a detection is in its lifecycle: open, claimed (active), or closed
class DetectionStatus(str, enum.Enum):
    open = "open"
    active = "active"
    closed = "closed"


# a person who can log into the platform and work detections
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


# an organization we're monitoring for security incidents
class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # how much this customer matters, from 1 (low) to 10 (critical) — feeds into priority scoring
    importance_level: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    detections: Mapped[List["Detection"]] = relationship(
        "Detection", back_populates="customer"
    )


# a rule that matches incoming incident data and turns it into a detection
class Signature(Base):
    __tablename__ = "signatures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    # whatever match criteria this signature needs — flexible so we don't have to change the database every time a new one comes along
    fields: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    detections: Mapped[List["Detection"]] = relationship(
        "Detection", back_populates="signature"
    )


# a security incident that matched a signature and is being tracked through to resolution
class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    signature_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("signatures.id"), nullable=False
    )
    customer_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("customers.id"), nullable=False
    )
    # locked in when the detection is created, so later changes to customer importance or signature severity don't reshuffle old detections
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[DetectionStatus] = mapped_column(
        Enum(DetectionStatus), nullable=False, default=DetectionStatus.open
    )
    # empty until an analyst claims the detection
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

    # speeds up the two things the queue screen does constantly: filtering by status and sorting by priority
    __table_args__ = (
        Index("ix_detections_status", "status"),
        Index("ix_detections_priority", "priority"),
    )


# hands each request its own database session and always closes it afterward, even if the request fails
def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
