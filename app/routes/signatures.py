from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import require_admin, require_readonly
from app.models import Signature, User, get_db
from app.schemas import SignatureCreate, SignatureUpdate

router = APIRouter(prefix="/signatures", tags=["signatures"])

templates = Jinja2Templates(directory="app/templates")


@router.get("", response_class=HTMLResponse)
def list_signatures(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_readonly),
):
    signatures = db.query(Signature).order_by(Signature.name).all()
    return templates.TemplateResponse(
        request,
        "signatures.html",
        {"signatures": signatures, "current_user": current_user},
    )


@router.post("")
def create_signature(
    payload: SignatureCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    signature = Signature(
        name=payload.name, priority=payload.priority, fields=payload.fields
    )
    db.add(signature)
    db.commit()
    return RedirectResponse(url="/signatures", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{signature_id}/update")
def update_signature(
    signature_id: int,
    payload: SignatureUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    signature = db.get(Signature, signature_id)
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Signature not found"
        )

    if payload.name is not None:
        signature.name = payload.name
    if payload.priority is not None:
        signature.priority = payload.priority
    if payload.fields is not None:
        signature.fields = payload.fields

    db.commit()
    return RedirectResponse(url="/signatures", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{signature_id}/delete")
def delete_signature(
    signature_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    signature = db.get(Signature, signature_id)
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Signature not found"
        )

    db.delete(signature)
    db.commit()
    return RedirectResponse(url="/signatures", status_code=status.HTTP_303_SEE_OTHER)
