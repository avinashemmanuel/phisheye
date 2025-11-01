# auth.py

from fastapi import Depends, HTTPException, Header
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import secrets

from database import get_db, User # Import from database.py

# --- Password Hashing Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Hashes a plain text password"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain text password against a hash"""
    return pwd_context.verify(plain_password, hashed_password)

# --- API Key Generation ---
def create_api_key() -> str:
    """Creates a new, secure 32-byte (64-char) API Key"""
    return secrets.token_hex(32)

# --- FastAPI Dependency ---
async def get_current_user(
        api_key: str | None = Header(default=None, alias="Authorization"),
        db: Session = Depends(get_db)
) -> User | None:
    """FastAPI dependency to get the current user from an API Key.
    If no key is provided, return None (a guest user).
    If a key is provided but is invalid, raises a 401 error"""
    if api_key is None:
        return None # This is a guest
    
    # We expect the header to be "Authorization: YOUR_KEY_HERE"
    # This setup allows for other schemes like "Bearer" later, but for now
    # it just checks the key itself.

    # Check if the key exists in the database
    user = db.query(User).filter(User.api_key == api_key).first()

    if user is None:
        # Key was provided but it's not valid
        raise HTTPException (
            status_code = 401,
            details = "Invalid API Key. Please register or get your Key from /login."
        )
    
    return user # This is a registered user  