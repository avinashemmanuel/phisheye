# database.py
import os
from datetime import datetime
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from typing import Generator

# --- Configuration ---
DATABASE_FILE = "phisheye.db"
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Models ---

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=True)

    # relationships
    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")
    feedback = relationship("Feedback", back_populates="owner", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    domain = Column(String, index=True, nullable=True)  # registered domain (for caching / invalidation)
    status = Column(String, nullable=False)  # e.g., 'safe', 'suspicious', 'dangerous'
    confidence = Column(Float, nullable=True)  # probability/confidence
    was_whitelisted = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    owner = relationship("User", back_populates="scans")
    feedback = relationship("Feedback", back_populates="scan", cascade="all, delete-orphan")


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    report_type = Column(String, nullable=False)  # 'false_positive' | 'false_negative' | other labels
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    scan = relationship("Scan", back_populates="feedback")
    owner = relationship("User", back_populates="feedback")


# --- Helpers ---

def create_db_and_tables() -> None:
    """Create SQLite DB file and all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator:
    """FastAPI dependency - yields a DB session and ensures it is closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Create DB file and tables on first import if needed
if not os.path.exists(DATABASE_FILE):
    create_db_and_tables()
else:
    # If DB exists, ensure metadata is available (no destructive changes here).
    Base.metadata.create_all(bind=engine)
