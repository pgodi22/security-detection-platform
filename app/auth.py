import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import Cookie, Depends, HTTPException, status
from jose import JWTError, jwt
import bcrypt as _bcrypt
from sqlalchemy.orm import Session

from app.models import User, UserRole, get_db

load_dotenv()

# must be set per deployment — we never want two environments sharing the same secret
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


# turns a plain password into something safe to store
def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()


# checks a login attempt against the stored password
def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())


# builds the login token a user's browser holds onto after signing in
def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    payload = data.copy()  # work on a copy so we don't change the caller's original data
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload["exp"] = expire
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# reads and validates a login token
def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        # don't tell the caller whether the token was expired or tampered with, just that it's invalid
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


# figures out who's making the request by reading their login cookie, which keeps the token out of reach of any page scripts
def get_current_user(
    access_token: Optional[str] = Cookie(default=None),
    db: Session = Depends(get_db),
) -> User:
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    payload = _decode_token(access_token)
    username: str = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


# blocks anyone who isn't an admin
def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# admins can do everything an analyst can, so both roles pass this check
def require_analyst(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in (UserRole.analyst, UserRole.admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or admin access required",
        )
    return current_user


# just confirms someone's logged in — used to guard pages any authenticated user is allowed to see
def require_readonly(current_user: User = Depends(get_current_user)) -> User:
    return current_user
