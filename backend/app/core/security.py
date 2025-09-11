"""
Security utilities for authentication and authorization.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.fernet import Fernet
import hashlib
import secrets
import base64

from .config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token security
security = HTTPBearer()

# Encryption for sensitive data


def get_encryption_key() -> bytes:
    """Get or generate encryption key for sensitive data."""
    key = settings.encryption_key.encode()
    return base64.urlsafe_b64encode(hashlib.sha256(key).digest())


cipher_suite = Fernet(get_encryption_key())


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Verify JWT token and return payload."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        return payload
    except JWTError:
        raise credentials_exception


def encrypt_sensitive_data(data: str) -> str:
    """Encrypt sensitive data for storage."""
    return cipher_suite.encrypt(data.encode()).decode()


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Decrypt sensitive data from storage."""
    return cipher_suite.decrypt(encrypted_data.encode()).decode()


def hash_identifier(identifier: str) -> str:
    """Hash an identifier with salt for anonymization."""
    salt = settings.hash_salt.encode()
    return hashlib.sha256(salt + identifier.encode()).hexdigest()


def generate_api_key() -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)


def sanitize_cloud_resource_id(resource_id: str) -> str:
    """Sanitize cloud resource ID by hashing while preserving prefix structure."""
    # Keep the prefix (like i-, vol-, sg-) for AWS resources
    if '-' in resource_id:
        parts = resource_id.split('-', 1)
        prefix = parts[0]
        identifier = parts[1]
        return f"{prefix}-{hash_identifier(identifier)[:12]}"
    else:
        return hash_identifier(resource_id)[:16]


def mask_sensitive_fields(data: Dict[str, Any], sensitive_fields: list = None) -> Dict[str, Any]:
    """Mask sensitive fields in data dictionary."""
    if sensitive_fields is None:
        sensitive_fields = [
            'password', 'secret', 'key', 'token', 'credential',
            'private', 'confidential', 'ssn', 'email', 'phone'
        ]

    masked_data = data.copy()

    for key, value in data.items():
        key_lower = key.lower()

        # Check if field name contains sensitive keywords
        if any(sensitive_word in key_lower for sensitive_word in sensitive_fields):
            if isinstance(value, str) and len(value) > 4:
                masked_data[key] = value[:2] + '*' * \
                    (len(value) - 4) + value[-2:]
            else:
                masked_data[key] = '***'

        # Recursively mask nested dictionaries
        elif isinstance(value, dict):
            masked_data[key] = mask_sensitive_fields(value, sensitive_fields)

        # Mask lists of dictionaries
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            masked_data[key] = [mask_sensitive_fields(
                item, sensitive_fields) for item in value]

    return masked_data


class SecurityHeaders:
    """Security headers middleware."""

    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get security headers for responses."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'",
        }
