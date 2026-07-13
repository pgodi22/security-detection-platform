from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth import get_current_user, require_analyst, require_readonly
from app.models import Customer, Detection, DetectionStatus, Signature, User, UserRole, get_db
from app.schemas import DetectionClose, DetectionResponse

router = APIRouter(prefix="/detections", tags=["detections"])

templates = Jinja2Templates(directory="app/templates")


@router.get("/queue", response_class=HTMLResponse)
def detection_queue(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_readonly),
):
    detections = (
        db.query(Detection)
        .filter(Detection.status == DetectionStatus.open)
        .order_by(Detection.priority.desc())
        .all()
    )
    can_claim = current_user.role in (UserRole.analyst, UserRole.admin)
    return templates.TemplateResponse(
        request,
        "queue.html",
        {
            "detections": detections,
            "current_user": current_user,
            "can_claim": can_claim,
        },
    )


@router.post("/queue/claim/{detection_id}")
def claim_detection(
    detection_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    detection = (
        db.query(Detection)
        .filter(Detection.id == detection_id)
        .with_for_update()
        .one_or_none()
    )
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found"
        )

    if detection.status != DetectionStatus.open:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Detection already claimed by another analyst",
        )

    detection.status = DetectionStatus.active
    detection.assigned_to = current_user.id
    db.commit()

    return RedirectResponse(
        url="/detections/queue", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("", response_class=HTMLResponse)
def detections_page(
    request: Request,
    search: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_readonly),
):
    query = db.query(Detection).join(Customer).join(Signature)

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(Customer.name.ilike(like), Signature.name.ilike(like))
        )

    if status_filter:
        try:
            query = query.filter(Detection.status == DetectionStatus(status_filter))
        except ValueError:
            pass

    detections = query.order_by(Detection.created_at.desc()).all()

    return templates.TemplateResponse(
        request,
        "detections.html",
        {
            "detections": detections,
            "search": search or "",
            "status_filter": status_filter or "",
            "current_user": current_user,
        },
    )


@router.get("/active", response_model=Optional[DetectionResponse])
def active_detection(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    detection = (
        db.query(Detection)
        .filter(
            Detection.status == DetectionStatus.active,
            Detection.assigned_to == current_user.id,
        )
        .first()
    )
    if not detection:
        return None
    return DetectionResponse.model_validate(detection)


@router.post("/close/{detection_id}")
def close_detection(
    detection_id: int,
    payload: DetectionClose,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    detection = db.get(Detection, detection_id)
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found"
        )

    if detection.assigned_to != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not own this detection",
        )

    detection.status = DetectionStatus.closed
    detection.resolution = payload.resolution
    db.commit()

    return RedirectResponse(
        url="/detections/queue", status_code=status.HTTP_303_SEE_OTHER
    )
