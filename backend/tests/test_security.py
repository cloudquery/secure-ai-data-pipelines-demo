import os
import secrets
from datetime import timedelta

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

for name in ("SECRET_KEY", "ENCRYPTION_KEY", "HASH_SALT"):
    os.environ.setdefault(name, secrets.token_hex(32))
os.environ.setdefault("DATABASE_URL", "postgresql://localhost/test")

from app.core.security import create_access_token, verify_token  # noqa: E402


def credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_token_round_trip():
    token = create_access_token({"sub": "user-1"})

    assert verify_token(credentials(token))["sub"] == "user-1"


def test_expired_token_is_rejected():
    token = create_access_token({"sub": "user-1"}, timedelta(seconds=-1))

    with pytest.raises(HTTPException) as error:
        verify_token(credentials(token))

    assert error.value.status_code == 401


def test_tampered_token_is_rejected():
    token = create_access_token({"sub": "user-1"})

    with pytest.raises(HTTPException) as error:
        verify_token(credentials(token[:-2] + "xx"))

    assert error.value.status_code == 401
