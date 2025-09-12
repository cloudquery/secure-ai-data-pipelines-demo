#!/usr/bin/env python3
"""
Base data processor class with common functionality for CloudQuery sync processing.
"""

import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, Any, Optional
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, text

# Add the app directory to the Python path
sys.path.append('/app')

from app.models.database import Base
from app.models.cloud_resources import CloudProvider, CloudAccount, CloudResource

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database connection
DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://cloudquery:secure_password@postgres:5432/cloudquery_security")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class BaseDataProcessor:
    """Base class for CloudQuery data processors with common functionality."""

    def __init__(self):
        self.db_session = SessionLocal()

    def _get_or_create_provider(self, provider_name: str) -> CloudProvider:
        """Get or create a cloud provider."""
        provider = self.db_session.query(CloudProvider).filter(
            CloudProvider.name == provider_name
        ).first()

        if not provider:
            provider = CloudProvider(
                name=provider_name,
                display_name=provider_name.upper(),
                description=f"{provider_name.upper()} cloud provider"
            )
            self.db_session.add(provider)
            self.db_session.commit()
            logger.info(f"Created new provider: {provider_name}")

        return provider

    def _get_or_create_account(self, provider: CloudProvider, account_id: str, 
                             account_name: str = None) -> CloudAccount:
        """Get or create a cloud account."""
        account = self.db_session.query(CloudAccount).filter(
            CloudAccount.provider_id == provider.id,
            CloudAccount.account_id == account_id
        ).first()

        if not account:
            account = CloudAccount(
                provider_id=provider.id,
                account_id=account_id,
                account_name=account_name or account_id,
                description=f"Account {account_id}"
            )
            self.db_session.add(account)
            self.db_session.commit()
            logger.info(f"Created new account: {account_id}")

        return account

    def _create_resource(self, account: CloudAccount, resource_type: str, 
                        resource_id: str, resource_name: str = None,
                        region: str = None, properties: Dict[str, Any] = None,
                        tags: Dict[str, str] = None) -> CloudResource:
        """Create a cloud resource."""
        resource = CloudResource(
            account_id=account.id,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name or resource_id,
            region=region,
            properties=properties or {},
            tags=tags or {},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        self.db_session.add(resource)
        return resource

    def _extract_tags(self, tags_data: Any) -> Dict[str, str]:
        """Extract tags from various tag formats."""
        if not tags_data:
            return {}
        
        if isinstance(tags_data, dict):
            return tags_data
        
        if isinstance(tags_data, str):
            try:
                return json.loads(tags_data)
            except json.JSONDecodeError:
                return {}
        
        return {}

    def _extract_properties(self, properties_data: Any) -> Dict[str, Any]:
        """Extract properties from various property formats."""
        if not properties_data:
            return {}
        
        if isinstance(properties_data, dict):
            return properties_data
        
        if isinstance(properties_data, str):
            try:
                return json.loads(properties_data)
            except json.JSONDecodeError:
                return {}
        
        return {}

    def update_processing_status(self, queue_id: int, status: str, 
                               error_message: str = None):
        """Update processing queue status."""
        try:
            self.db_session.execute(text("""
                UPDATE sync_processing_queue 
                SET status = :status, 
                    error_message = :error_message,
                    updated_at = NOW()
                WHERE id = :queue_id
            """), {
                'status': status,
                'error_message': error_message,
                'queue_id': queue_id
            })
            self.db_session.commit()
        except Exception as e:
            logger.error(f"Error updating processing status: {e}")
            self.db_session.rollback()

    def __del__(self):
        """Clean up database session."""
        if hasattr(self, 'db_session'):
            self.db_session.close()
