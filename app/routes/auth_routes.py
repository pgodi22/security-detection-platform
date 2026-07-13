from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import create_access_token, verify_password
from app.models import User, get_db

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")


@router.post("/auth/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return RedirectResponse(
            url="/login?error=Invalid+username+or+password",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    token = create_access_token({"sub": user.username})

    response = RedirectResponse(
        url="/detections/queue", status_code=status.HTTP_303_SEE_OTHER
    )
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
    )
    return response


@router.post("/auth/logout")
def logout():
    response = RedirectResponse(
        url="/login", status_code=status.HTTP_303_SEE_OTHER
    )
    response.delete_cookie(key="access_token")
    return response
