import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine, Session
from sqlmodel.pool import StaticPool

from app.main import app
from app.db import get_session
from app.auth import hash_password
from app.models import User


# ── in-memory SQLite DB just for tests ──────────────────────────────
@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(User(username="admin",  password_hash=hash_password("admin123"),  role="admin"))
        session.add(User(username="vendor", password_hash=hash_password("vendor123"), role="vendor"))
        session.commit()
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def override_get_session():
        yield session

    app.dependency_overrides[get_session] = override_get_session
    client = TestClient(app, raise_server_exceptions=False)
    yield client
    app.dependency_overrides.clear()


# ── helper ───────────────────────────────────────────────────────────
def get_token(client, username, password):
    resp = client.post("/token", data={"username": username, "password": password})
    return resp.json()["access_token"]


# ── tests ────────────────────────────────────────────────────────────
def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_login_success(client):
    resp = client.post("/token", data={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password(client):
    resp = client.post("/token", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_me(client):
    token = get_token(client, "admin", "admin123")
    resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"
    assert resp.json()["role"] == "admin"


def test_me_unauthenticated(client):
    resp = client.get("/me")
    assert resp.status_code == 401


def test_create_order_as_admin(client):
    token = get_token(client, "admin", "admin123")
    resp = client.post("/orders", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "created"


def test_create_order_as_vendor_forbidden(client):
    token = get_token(client, "vendor", "vendor123")
    resp = client.post("/orders", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_list_orders(client):
    token = get_token(client, "admin", "admin123")
    client.post("/orders", headers={"Authorization": f"Bearer {token}"})
    resp = client.get("/orders", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
