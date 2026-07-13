from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.models import Customer, Detection, DetectionStatus, Signature, get_db
from app.schemas import DetectionResponse, IncidentIngestion

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _find_best_signature(
    signatures: list[Signature], incoming: dict[str, str]
) -> Signature | None:
    """Return the highest-priority signature whose fields are a subset of incoming,
    or None if no signature matches.

    'Highest priority' means the largest priority integer value. When two
    signatures tie on priority, the one with the most specific match (most
    fields) wins; remaining ties are broken by lowest id for determinism.
    """
    matches = [
        sig for sig in signatures
        if sig.fields and sig.fields.items() <= incoming.items()
    ]
    if not matches:
        return None
    return max(matches, key=lambda s: (s.priority, len(s.fields), -s.id))


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

    # No signature matched: return a 200 with a clear message rather than
    # raising an error. The external source should not be penalised for
    # sending data that has no matching rule yet. A future unmatched_incidents
    # table or dead-letter queue can slot in here without changing the
    # external contract.
    if matched is None:
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

    # Eager-load relationships so DetectionResponse can read .customer.name
    # and .signature.name without a second round-trip.
    _ = detection.customer
    _ = detection.signature

    return DetectionResponse.model_validate(detection)
