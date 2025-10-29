# database.py

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from datetime import datetime 
import os 

# Database Setup
DATABASE_FILE = "phisheye.db" # Name of SQLite file
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

# Engine that connects to the database
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False} # check_same_thread is required for SQLite
)

# The session the app will use to talk to the database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# The "Base" class the table models will inherit from 
Base = declarative_base()

# ---DATABASE MODELS---

# Table to log every scan (for Feature 1 & 2)
class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    status = Column(String) # 'Safe', 'Suspicious', 'Dangerous'
    confidence = Column(Float)
    was_whitelisted = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # This creates a one-to-many relationship with the Feedback table
    feedback = relationship("Feedback", back_populates="scan")

# Table to store user feedback (for Feature 1)
class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id")) # Links this to a specific scan
    report_type = Column(String) # e.g., 'false-positive' (was safe) or 'false-negative' (was dangerous)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Links back to scan table
    scan = relationship("Scan", back_populates="feedback")

# --- Helper Function ---
def get_db():
    """Dependecy for FastAPI to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_db_and_tables():
    """Creates the database files and all tables."""
    if not os.path.exists(DATABASE_FILE):
        print(f"Creating database and tables at {DATABASE_URL} ...")
        Base.metadata.create_all(bind=engine)
    else:
        print("Database already exists!")
