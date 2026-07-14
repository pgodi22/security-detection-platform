import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import hash_password
from app.main import app
from app.models import Base, User, UserRole, get_db

SEED_USERS = {
    "admin": ("admin123", UserRole.admin),
    "analyst": ("analyst123", UserRole.analyst),
    "readonly": ("readonly123", UserRole.readonly),
}

# one shared in-memory db for the whole test run; StaticPool keeps it alive
# across connections since a plain ":memory:" db disappears when a connection closes
engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(bind=engine)


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture
def client():
    Base.metadata.create_all(bind=engine)

    db = TestingSessionLocal()
    for username, (password, role) in SEED_USERS.items():
        db.add(User(username=username, hashed_password=hash_password(password), role=role))
    db.commit()
    db.close()

    yield TestClient(app)

    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(client):
    db = TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture
def login_as(client):
    # logs a seeded user in through the real /auth/login flow and hands back
    # the cookie so a test can act as that user on later requests
    def _login(username: str) -> dict:
        password, _ = SEED_USERS[username]
        response = client.post(
            "/auth/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )
        assert response.status_code == 303, f"login failed for {username}: {response.text}"
        return {"access_token": response.cookies["access_token"]}

    return _login
