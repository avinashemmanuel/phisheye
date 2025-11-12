# auth.py
"""
Authentication helpers for PhishEye.

Exports:
- hash_password(plain_password) -> str
- verify_password(plain_password, hashed_password) -> bool
- create_api_key() -> str
- get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)) -> User | None

Notes:
- Passwords are hashed using PBKDF2-HMAC-SHA256 with a 16-byte random salt and 100k iterations.
  The stored format is: salt_hex$dk_hex
- If your existing database uses bcrypt (hash starts with "$2"), this module will try to use
  the `bcrypt` package to verify those hashes if bcrypt is installed in your environment.
"""

import os
import hmac
import hashlib
import base64
from typing import Optional

from fastapi import Depends, Header
from sqlalchemy.orm import Session

# Try to import bcrypt for backward-compatibility with bcrypt-stored hashes (optional)
try:
    import bcrypt  # type: ignore
    _HAS_BCRYPT = True
except Exception:
    _HAS_BCRYPT = False

# Import DB helpers / User model (must match your database.py)
from database import get_db, User


# ----- Password hashing utilities (PBKDF2-SHA256) -----

_PBKDF2_ITERATIONS = 100_000
_SALT_BYTES = 16  # 16 bytes -> 32 hex chars


def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password using PBKDF2-HMAC-SHA256.
    Returns string in the format: salt_hex$dk_hex
    """
    if not isinstance(plain_password, str):
        raise TypeError("Password must be a string")

    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256", plain_password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return f"{salt.hex()}${dk.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored hash.
    Supports:
      - PBKDF2 format: salt_hex$dk_hex
      - bcrypt (if bcrypt is available): "$2..." format
      - fallback plain equality (only if neither format matches) — not recommended
    """
    if not isinstance(plain_password, str) or not isinstance(stored_hash, str):
        return False

    # 1) bcrypt (if present and stored hash looks like bcrypt)
    if stored_hash.startswith("$2") and _HAS_BCRYPT:
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
        except Exception:
            return False

    # 2) PBKDF2 salt$dk format
    if "$" in stored_hash:
        try:
            salt_hex, dk_hex = stored_hash.split("$", 1)
            salt = bytes.fromhex(salt_hex)
            expected_dk = bytes.fromhex(dk_hex)
            computed = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
            return hmac.compare_digest(computed, expected_dk)
        except Exception:
            return False

    # 3) Fallback (in case your DB currently stores plain text — not recommended)
    # This is only a compatibility fallback: if you see this used, consider re-hashing user passwords.
    try:
        return hmac.compare_digest(plain_password, stored_hash)
    except Exception:
        return False


# ----- API key generation -----

def create_api_key() -> str:
    """
    Create a 32-byte random URL-safe API key (base64url without padding).
    """
    token = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").rstrip("=")
    return token


# ----- Dependency: get_current_user -----

async def get_current_user(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    FastAPI dependency to resolve the current user from the Authorization header.

    Behavior:
    - If no Authorization header is present, returns None.
    - If Authorization present and contains a Bearer API key that matches a user, returns that User.
    - If header present but no user matches, returns None.
    - This function intentionally does NOT raise HTTPException on missing/invalid token,
      because some endpoints allow anonymous access and enforce authentication themselves.
    """
    if not authorization:
        return None

    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()

    if not token:
        return None

    try:
        user = db.query(User).filter(User.api_key == token).first()
        return user
    except Exception:
        # In case the DB call errors out for any reason, be safe and return None.
        return None
