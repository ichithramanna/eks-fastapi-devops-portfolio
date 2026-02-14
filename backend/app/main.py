from typing import List
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from .db import create_db_and_tables, get_session, engine
from .models import Order, User
from .auth import authenticate_user, create_access_token, get_current_user, hash_password

app = FastAPI(title="Order Workflow API v1")

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

    # Seed 3 demo users if DB is empty (simple for v1)
    # admin/admin123, vendor/vendor123, driver/driver123
    with Session(engine) as session: # quick v1 shortcut
        existing = session.exec(select(User)).first()
        if not existing:
            session.add(User(username="admin",  password_hash=hash_password("admin123"),  role="admin"))
            session.add(User(username="vendor", password_hash=hash_password("vendor123"), role="vendor"))
            session.add(User(username="driver", password_hash=hash_password("driver123"), role="driver"))
            session.commit()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/token")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    # OAuth2PasswordRequestForm provides username/password as form fields (not JSON). [page:14]
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(user.username)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role}

@app.post("/orders", response_model=Order)
def create_order(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    order = Order()
    session.add(order)
    session.commit()
    session.refresh(order)
    return order

@app.get("/orders", response_model=List[Order])
def list_orders(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    return session.exec(select(Order)).all()

from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)
