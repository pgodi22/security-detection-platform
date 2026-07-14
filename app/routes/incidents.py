from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.models import Customer, Detection, DetectionStatus, Signature, get_db
from app.schemas import DetectionResponse, IncidentIngestion

router = APIRouter(prefix="/incidents", tags=["incidents"])


# figures out which signature this incident matches, picking the most specific one when there's a tie
def _find_best_signature(
    signatures: list[Signature], incoming: dict[str, str]
) -> Signature | None:
    matches = [
        sig for sig in signatures
        # skip signatures with no criteria set — otherwise they'd match every single incident
        if sig.fields and sig.fields.items() <= incoming.items()
    ]
    if not matches:
        return None
    # if it's still a tie, go with whichever signature was created first
    return max(matches, key=lambda s: (s.priority, len(s.fields), -s.id))


# the endpoint external systems call to report a raw incident and (maybe) turn it into a detection
@router.post("/ingest", response_model=DetectionResponse)
def ingest_incident(payload: IncidentIngestion, db: Session = Depends(get_db)):
    customer = db.get(Customer, payload.customer_id)
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Customer {payload.customer_id} not found",
        )

    signatures = db.query(Signature).all()
    matched = _find_best_signature(signatures, payload.fields)

    # there's no rule for this yet, so we accept the incident instead of rejecting it
    if matched is None:
        # no detection was created, so we send back a plain response instead of the usual one
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "matched": False,
                "message": (
                    "No signature matched the supplied fields. "
                    "Incident was received but no Detection was created."
                ),
                "customer_id": payload.customer_id,
                "fields": payload.fields,
            },
        )

    # multiplies importance and severity together, so a big customer with a small issue can still outrank a small customer with a big one (see the priority formula under Architecture Decisions in README.md)
    priority = customer.importance_level * matched.priority

    detection = Detection(
        signature_id=matched.id,
        customer_id=customer.id,
        priority=priority,
        status=DetectionStatus.open,
        assigned_to=None,
    )
    db.add(detection)
    db.commit()
    db.refresh(detection)

    # loads the customer and signature names now, before the database connection closes
    _ = detection.customer
    _ = detection.signature

    return DetectionResponse.model_validate(detection)
