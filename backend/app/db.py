import os
from sqlmodel import SQLModel, Session, create_engine
from . import models

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://app:app_password@localhost:5432/orders",
)

engine = create_engine(DATABASE_URL)

def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

