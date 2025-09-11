"""
Data sanitization service for removing PII and sensitive information.
"""
import re
import hashlib
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import json

from ..core.config import settings
from ..core.security import hash_identifier, encrypt_sensitive_data


class DataSanitizer:
    """Service for sanitizing cloud resource data."""

    def __init__(self):
        self.pii_patterns = self._get_pii_patterns()
        self.sensitive_keys = self._get_sensitive_keys()
        self.preserve_structure = True

    def sanitize_cloud_resource(self, resource_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize cloud resource data by removing PII and sensitive information.

        Args:
            resource_data: Raw cloud resource data

        Returns:
            Sanitized resource data with PII removed/anonymized
        """

        if not isinstance(resource_data, dict):
            return resource_data

        sanitized = {}

        for key, value in resource_data.items():
            # Check if key is sensitive
            if self._is_sensitive_key(key):
                sanitized[key] = self._sanitize_sensitive_value(value, key)
            else:
                sanitized[key] = self._sanitize_value(value, key)

        return sanitized

    def apply_differential_privacy(
        self,
        numeric_data: Union[int, float],
        epsilon: float = 1.0,
        sensitivity: float = 1.0
    ) -> Union[int, float]:
        """
        Apply differential privacy to numeric data using Laplace mechanism.

        Args:
            numeric_data: Original numeric value
            epsilon: Privacy parameter (lower = more private)
            sensitivity: Sensitivity of the query

        Returns:
            Differentially private numeric value
        """
        import random

        # Add Laplace noise
        scale = sensitivity / epsilon
        noise = random.laplace(0, scale)

        if isinstance(numeric_data, int):
            return max(0, int(numeric_data + noise))
        else:
            return max(0.0, float(numeric_data + noise))

    def hash_sensitive_identifiers(self, identifier: str) -> str:
        """
        Hash sensitive identifiers while preserving format structure.

        Args:
            identifier: Original identifier

        Returns:
            Hashed identifier maintaining structure
        """
        return hash_identifier(identifier)

    def anonymize_ip_addresses(self, ip_address: str) -> str:
        """
        Anonymize IP addresses by zeroing out the last octet.

        Args:
            ip_address: Original IP address

        Returns:
            Anonymized IP address
        """
        if self._is_ipv4(ip_address):
            parts = ip_address.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        elif self._is_ipv6(ip_address):
            # For IPv6, zero out the last 64 bits
            parts = ip_address.split(':')
            if len(parts) >= 4:
                return ':'.join(parts[:4]) + '::0'

        return "x.x.x.x"  # Fallback for invalid IPs

    def mask_email_addresses(self, email: str) -> str:
        """
        Mask email addresses while preserving domain structure.

        Args:
            email: Original email address

        Returns:
            Masked email address
        """
        if '@' in email:
            local, domain = email.split('@', 1)
            masked_local = local[0] + '*' * \
                (len(local) - 2) + local[-1] if len(local) > 2 else '***'
            return f"{masked_local}@{domain}"

        return "***@***.***"

    def sanitize_configuration_block(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize configuration blocks with special handling for nested structures.

        Args:
            config: Configuration dictionary

        Returns:
            Sanitized configuration
        """
        if not isinstance(config, dict):
            return config

        sanitized = {}

        for key, value in config.items():
            if isinstance(value, dict):
                sanitized[key] = self.sanitize_configuration_block(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_configuration_block(item) if isinstance(
                        item, dict) else self._sanitize_value(item, key)
                    for item in value
                ]
            else:
                sanitized[key] = self._sanitize_value(value, key)

        return sanitized

    def _sanitize_value(self, value: Any, key: str) -> Any:
        """Sanitize a single value based on its content and key."""

        if value is None:
            return None

        if isinstance(value, dict):
            return self.sanitize_configuration_block(value)
        elif isinstance(value, list):
            return [self._sanitize_value(item, key) for item in value]
        elif isinstance(value, str):
            return self._sanitize_string_value(value, key)
        elif isinstance(value, (int, float)):
            # Apply differential privacy to certain numeric fields
            if self._should_apply_dp(key):
                return self.apply_differential_privacy(value)
            return value
        else:
            return value

    def _sanitize_sensitive_value(self, value: Any, key: str) -> Any:
        """Sanitize values for sensitive keys."""

        if isinstance(value, str):
            if len(value) > 4:
                return value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                return '***'
        elif isinstance(value, dict):
            return {k: self._sanitize_sensitive_value(v, k) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._sanitize_sensitive_value(item, key) for item in value]
        else:
            return '***'

    def _sanitize_string_value(self, value: str, key: str) -> str:
        """Sanitize string values based on patterns and context."""

        # Check for PII patterns
        for pattern_name, pattern in self.pii_patterns.items():
            if pattern.search(value):
                if pattern_name == 'email':
                    return self.mask_email_addresses(value)
                elif pattern_name == 'ip_address':
                    return self.anonymize_ip_addresses(value)
                elif pattern_name in ['ssn', 'credit_card', 'phone']:
                    return self._mask_pattern(value, pattern)
                else:
                    return self.hash_sensitive_identifiers(value)

        # Check for cloud resource identifiers
        if self._is_cloud_resource_id(value):
            return self._sanitize_cloud_id(value)

        # Check for ARNs
        if value.startswith('arn:'):
            return self._sanitize_arn(value)

        return value

    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a key is considered sensitive."""
        key_lower = key.lower()
        return any(sensitive in key_lower for sensitive in self.sensitive_keys)

    def _should_apply_dp(self, key: str) -> bool:
        """Check if differential privacy should be applied to this key."""
        dp_keys = ['count', 'size', 'capacity', 'volume', 'memory', 'cpu']
        key_lower = key.lower()
        return any(dp_key in key_lower for dp_key in dp_keys)

    def _is_cloud_resource_id(self, value: str) -> bool:
        """Check if value looks like a cloud resource identifier."""
        # AWS resource ID patterns
        aws_patterns = [
            r'^i-[0-9a-f]{8,17}$',  # EC2 instances
            r'^vol-[0-9a-f]{8,17}$',  # EBS volumes
            r'^sg-[0-9a-f]{8,17}$',  # Security groups
            r'^vpc-[0-9a-f]{8,17}$',  # VPCs
            r'^subnet-[0-9a-f]{8,17}$',  # Subnets
        ]

        # GCP resource ID patterns
        gcp_patterns = [
            r'^[0-9]{10,20}$',  # Numeric IDs
            r'^projects/[^/]+/zones/[^/]+/instances/[^/]+$',  # Instance URLs
        ]

        # Azure resource ID patterns
        azure_patterns = [
            r'^/subscriptions/[0-9a-f-]{36}/resourceGroups/',  # Resource IDs
        ]

        all_patterns = aws_patterns + gcp_patterns + azure_patterns

        for pattern in all_patterns:
            if re.match(pattern, value):
                return True

        return False

    def _sanitize_cloud_id(self, cloud_id: str) -> str:
        """Sanitize cloud resource IDs while preserving structure."""
        # For AWS IDs, keep the prefix
        if '-' in cloud_id:
            parts = cloud_id.split('-', 1)
            prefix = parts[0]
            identifier = parts[1]
            return f"{prefix}-{hash_identifier(identifier)[:12]}"
        else:
            return hash_identifier(cloud_id)[:16]

    def _sanitize_arn(self, arn: str) -> str:
        """Sanitize AWS ARNs while preserving structure."""
        parts = arn.split(':')
        if len(parts) >= 6:
            # Keep service and region, sanitize account and resource
            parts[4] = hash_identifier(parts[4])[:12]  # Account ID

            # Sanitize resource part
            resource_part = parts[-1]
            if '/' in resource_part:
                resource_type, resource_id = resource_part.split('/', 1)
                parts[-1] = f"{resource_type}/{hash_identifier(resource_id)[:16]}"
            else:
                parts[-1] = hash_identifier(resource_part)[:16]

            return ':'.join(parts)

        return hash_identifier(arn)

    def _mask_pattern(self, value: str, pattern: re.Pattern) -> str:
        """Mask sensitive patterns in strings."""
        def mask_match(match):
            matched = match.group()
            if len(matched) <= 4:
                return '*' * len(matched)
            else:
                return matched[:2] + '*' * (len(matched) - 4) + matched[-2:]

        return pattern.sub(mask_match, value)

    def _is_ipv4(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False

    def _is_ipv6(self, ip: str) -> bool:
        """Check if string is a valid IPv6 address."""
        try:
            import ipaddress
            ipaddress.IPv6Address(ip)
            return True
        except (ValueError, AttributeError):
            return False

    def _get_pii_patterns(self) -> Dict[str, re.Pattern]:
        """Get regex patterns for PII detection."""
        return {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'credit_card': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
            'phone': re.compile(r'\b\d{3}[-.]\d{3}[-.]\d{4}\b'),
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'mac_address': re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b'),
        }

    def _get_sensitive_keys(self) -> List[str]:
        """Get list of sensitive key patterns."""
        return [
            'password', 'passwd', 'pwd',
            'secret', 'key', 'token', 'credential',
            'private', 'confidential',
            'ssn', 'social_security',
            'email', 'mail',
            'phone', 'telephone', 'mobile',
            'address', 'location',
            'name', 'firstname', 'lastname',
            'dob', 'birth', 'birthday',
            'license', 'passport',
            'card', 'account', 'number'
        ]

# Example function to demonstrate usage


def sanitize_cloud_resource(resource_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main function to sanitize cloud resource data.

    Args:
        resource_data: Raw cloud resource data from CloudQuery

    Returns:
        Sanitized resource data safe for AI analysis
    """
    sanitizer = DataSanitizer()

    # Apply sanitization
    sanitized_data = sanitizer.sanitize_cloud_resource(resource_data)

    # Add metadata about sanitization
    sanitized_data['_sanitization_metadata'] = {
        'sanitized_at': datetime.utcnow().isoformat(),
        'sanitizer_version': '1.0.0',
        'techniques_applied': [
            'pii_removal',
            'identifier_hashing',
            'differential_privacy',
            'data_masking'
        ]
    }

    return sanitized_data
