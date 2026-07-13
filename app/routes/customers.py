from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import require_admin, require_readonly
from app.models import Customer, User, get_db
from app.schemas import CustomerCreate, CustomerUpdate

router = APIRouter(prefix="/customers", tags=["customers"])

templates = Jinja2Templates(directory="app/templates")


@router.get("", response_class=HTMLResponse)
def list_customers(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_readonly),
):
    customers = db.query(Customer).order_by(Customer.name).all()
    return templates.TemplateResponse(
        request,
        "customers.html",
        {"customers": customers, "current_user": current_user},
    )


@router.post("")
def create_customer(
    payload: CustomerCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    customer = Customer(name=payload.name, importance_level=payload.importance_level)
    db.add(customer)
    db.commit()
    return RedirectResponse(url="/customers", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{customer_id}/update")
def update_customer(
    customer_id: int,
    payload: CustomerUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    customer = db.get(Customer, customer_id)
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found"
        )

    if payload.name is not None:
        customer.name = payload.name
    if payload.importance_level is not None:
        customer.importance_level = payload.importance_level

    db.commit()
    return RedirectResponse(url="/customers", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{customer_id}/delete")
def delete_customer(
    customer_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    customer = db.get(Customer, customer_id)
    if not customer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Customer not found"
        )

    db.delete(customer)
    db.commit()
    return RedirectResponse(url="/customers", status_code=status.HTTP_303_SEE_OTHER)
