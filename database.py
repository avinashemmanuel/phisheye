# database.py

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from datetime import datetime
import os

# --- Database Setup ---
DATABASE_FILE = "phisheye.db" # This will be the name of your SQLite file
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Database Table Models ---

# NEW: User table (for Feature 3)
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True)
    
    # Relationships
    scans = relationship("Scan", back_populates="owner")
    feedback = relationship("Feedback", back_populates="owner")
    custom_lists = relationship("CustomList", back_populates="owner")

# UPDATED: Scan table now links to a user
class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    status = Column(String)
    confidence = Column(Float)
    was_whitelisted = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user_id = Column(Integer, ForeignKey("users.id")) # <-- NEW LINK
    
    owner = relationship("User", back_populates="scans")
    feedback = relationship("Feedback", back_populates="scan")

# UPDATED: Feedback table now links to a user
class Feedback(Base):
    __tablename__ = "feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    report_type = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user_id = Column(Integer, ForeignKey("users.id")) # <-- NEW LINK
    
    scan = relationship("Scan", back_populates="feedback")
    owner = relationship("User", back_populates="feedback")

# NEW: CustomList table (for Feature 3)
class CustomList(Base):
    __tablename__ = "custom_lists"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, index=True)
    list_type = Column(String) # 'whitelist' or 'blacklist'
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    owner = relationship("User", back_populates="custom_lists")


# --- Helper Function ---
def get_db():
    """Dependency for FastAPI to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_db_and_tables():
    """Creates the database file and all tables."""
    print("Creating database and tables...")
    Base.metadata.create_all(bind=engine)

# Run this check. If the file doesn't exist, create it.
if not os.path.exists(DATABASE_FILE):
    create_db_and_tables()
else:
    # This is a simple way to check if the schema is old.
    # A better way is to use Alembic for migrations.
    print("Database already exists.")