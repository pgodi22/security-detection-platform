from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models import DetectionStatus, UserRole


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------


class UserBase(BaseModel):
    username: str
    role: UserRole = UserRole.readonly


class UserCreate(UserBase):
    password: str  # plain-text; route handler hashes before storing


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime


# ---------------------------------------------------------------------------
# Customer
# ---------------------------------------------------------------------------


class CustomerBase(BaseModel):
    name: str
    importance_level: int = Field(..., ge=1, le=10)


class CustomerCreate(CustomerBase):
    pass


class CustomerUpdate(BaseModel):
    name: Optional[str] = None
    importance_level: Optional[int] = Field(None, ge=1, le=10)


class CustomerResponse(CustomerBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------


class SignatureBase(BaseModel):
    name: str
    priority: int
    fields: dict[str, str]


class SignatureCreate(SignatureBase):
    pass


class SignatureUpdate(BaseModel):
    name: Optional[str] = None
    priority: Optional[int] = None
    fields: Optional[dict[str, str]] = None


class SignatureResponse(SignatureBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class DetectionBase(BaseModel):
    signature_id: int
    customer_id: int
    priority: int
    status: DetectionStatus = DetectionStatus.open
    assigned_to: Optional[int] = None


class DetectionResponse(DetectionBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    resolution: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    customer_name: str
    signature_name: str

    @model_validator(mode="before")
    @classmethod
    def _extract_related_names(cls, data):
        if isinstance(data, dict):
            return data
        return {
            "id": data.id,
            "signature_id": data.signature_id,
            "customer_id": data.customer_id,
            "priority": data.priority,
            "status": data.status,
            "assigned_to": data.assigned_to,
            "resolution": data.resolution,
            "created_at": data.created_at,
            "updated_at": data.updated_at,
            "customer_name": data.customer.name if data.customer else "",
            "signature_name": data.signature.name if data.signature else "",
        }


# ---------------------------------------------------------------------------
# Incident ingestion
# ---------------------------------------------------------------------------


class IncidentIngestion(BaseModel):
    customer_id: int
    fields: dict[str, str]


# ---------------------------------------------------------------------------
# Detection close
# ---------------------------------------------------------------------------


class DetectionClose(BaseModel):
    resolution: str

    @field_validator("resolution")
    @classmethod
    def _resolution_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("resolution cannot be empty")
        return v.strip()
