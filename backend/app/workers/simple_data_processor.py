#!/usr/bin/env python3
"""
Simple background data processor for automatic CloudQuery sync processing.
Listens for database notifications and processes new data automatically.
"""

from app.models.database import Base
from app.models.cloud_resources import CloudProvider, CloudAccount, CloudResource
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, Any, Optional
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, text

# Add the app directory to the Python path
sys.path.append('/app')


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


class SimpleDataProcessor:
    """Simple background processor for CloudQuery sync data."""

    def __init__(self):
        self.db_session = SessionLocal()

    def process_azure_data(self, table_name: str) -> int:
        """Process Azure data from CloudQuery tables."""
        logger.info(f"Processing Azure data from {table_name}")

        try:
            # Get Azure resources based on table name
            if 'storage_accounts' in table_name:
                resources = self.db_session.execute(text("""
                    SELECT 
                        subscription_id,
                        id,
                        name,
                        location,
                        properties,
                        tags
                    FROM azure_storage_accounts
                    WHERE _cq_sync_time > NOW() - INTERVAL '1 hour'
                    LIMIT 50
                """)).fetchall()

                return self._process_storage_accounts(resources)

            elif 'network_security_groups' in table_name:
                resources = self.db_session.execute(text("""
                    SELECT 
                        subscription_id,
                        id,
                        name,
                        location,
                        properties,
                        tags
                    FROM azure_network_security_groups
                    WHERE _cq_sync_time > NOW() - INTERVAL '1 hour'
                    LIMIT 50
                """)).fetchall()

                return self._process_network_security_groups(resources)

            elif 'virtual_networks' in table_name:
                resources = self.db_session.execute(text("""
                    SELECT 
                        subscription_id,
                        id,
                        name,
                        location,
                        properties,
                        tags
                    FROM azure_network_virtual_networks
                    WHERE _cq_sync_time > NOW() - INTERVAL '1 hour'
                    LIMIT 50
                """)).fetchall()

                return self._process_virtual_networks(resources)

            else:
                logger.info(f"No specific processor for table {table_name}")
                return 0

        except Exception as e:
            logger.error(f"Error processing Azure data from {table_name}: {e}")
            raise

    def process_aws_data(self, table_name: str) -> int:
        """Process AWS data from CloudQuery tables."""
        logger.info(f"Processing AWS data from {table_name}")

        try:
            # Get AWS resources based on table name
            if 's3_buckets' in table_name:
                resources = self.db_session.execute(text("""
                    SELECT 
                        account_id,
                        arn,
                        name,
                        region,
                        creation_date,
                        policy_status,
                        tags
                    FROM aws_s3_buckets
                    WHERE _cq_sync_time > NOW() - INTERVAL '1 hour'
                    LIMIT 50
                """)).fetchall()

                return self._process_s3_buckets(resources)

            elif 'iam_users' in table_name:
                resources = self.db_session.execute(text("""
                    SELECT 
                        account_id,
                        arn,
                        user_name,
                        create_date,
                        path,
                        tags
                    FROM aws_iam_users
                    WHERE _cq_sync_time > NOW() - INTERVAL '1 hour'
                    LIMIT 50
                """)).fetchall()

                return self._process_iam_users(resources)

            elif 'ec2_instances' in table_name:
                resources = self.db_session.execute(text("""
                    SELECT 
                        account_id,
                        arn,
                        instance_id,
                        instance_type,
                        state,
                        region,
                        availability_zone,
                        vpc_id,
                        subnet_id,
                        tags
                    FROM aws_ec2_instances
                    WHERE _cq_sync_time > NOW() - INTERVAL '1 hour'
                    LIMIT 50
                """)).fetchall()

                return self._process_ec2_instances(resources)

            else:
                logger.info(
                    f"No specific processor for AWS table {table_name}")
                return 0

        except Exception as e:
            logger.error(f"Error processing AWS data from {table_name}: {e}")
            raise

    def process_gcp_data(self, table_name: str) -> int:
        """Process GCP data from CloudQuery tables."""
        logger.info(f"Processing GCP data from {table_name}")
        # TODO: Implement GCP processing
        return 0

    def _process_storage_accounts(self, resources) -> int:
        """Process Azure storage accounts."""
        if not resources:
            return 0

        # Get or create Azure provider and account
        provider = self._get_or_create_provider('azure')
        subscription_id = resources[0][0]
        account = self._get_or_create_account(provider.id, subscription_id)

        processed_count = 0
        for resource in resources:
            try:
                properties = resource[4] or {}
                allow_blob_public_access = properties.get(
                    'allowBlobPublicAccess', False)

                cloud_resource = CloudResource(
                    provider_id=provider.id,
                    account_id=account.id,
                    resource_id=resource[1] or '',
                    resource_name=resource[2] or '',
                    resource_type='storage_account',
                    service_name='storage',
                    region=resource[3] or 'unknown',
                    state='active',
                    configuration={'properties': properties},
                    tags=resource[5] or {},
                    public_access=allow_blob_public_access,
                    encryption_enabled=True,
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow()
                )

                self.db_session.add(cloud_resource)
                processed_count += 1

            except Exception as e:
                logger.error(
                    f"Error processing storage account {resource[1]}: {e}")
                continue

        self.db_session.commit()
        logger.info(f"Processed {processed_count} storage accounts")
        return processed_count

    def _process_network_security_groups(self, resources) -> int:
        """Process Azure network security groups."""
        if not resources:
            return 0

        provider = self._get_or_create_provider('azure')
        subscription_id = resources[0][0]
        account = self._get_or_create_account(provider.id, subscription_id)

        processed_count = 0
        for resource in resources:
            try:
                properties = resource[4] or {}

                cloud_resource = CloudResource(
                    provider_id=provider.id,
                    account_id=account.id,
                    resource_id=resource[1] or '',
                    resource_name=resource[2] or '',
                    resource_type='network_security_group',
                    service_name='network',
                    region=resource[3] or 'unknown',
                    state='active',
                    configuration={'properties': properties},
                    tags=resource[5] or {},
                    public_access=False,
                    encryption_enabled=False,
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow()
                )

                self.db_session.add(cloud_resource)
                processed_count += 1

            except Exception as e:
                logger.error(f"Error processing NSG {resource[1]}: {e}")
                continue

        self.db_session.commit()
        logger.info(f"Processed {processed_count} network security groups")
        return processed_count

    def _process_virtual_networks(self, resources) -> int:
        """Process Azure virtual networks."""
        if not resources:
            return 0

        provider = self._get_or_create_provider('azure')
        subscription_id = resources[0][0]
        account = self._get_or_create_account(provider.id, subscription_id)

        processed_count = 0
        for resource in resources:
            try:
                properties = resource[4] or {}

                cloud_resource = CloudResource(
                    provider_id=provider.id,
                    account_id=account.id,
                    resource_id=resource[1] or '',
                    resource_name=resource[2] or '',
                    resource_type='virtual_network',
                    service_name='network',
                    region=resource[3] or 'unknown',
                    state='active',
                    configuration={'properties': properties},
                    tags=resource[5] or {},
                    public_access=False,
                    encryption_enabled=False,
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow()
                )

                self.db_session.add(cloud_resource)
                processed_count += 1

            except Exception as e:
                logger.error(f"Error processing VNet {resource[1]}: {e}")
                continue

        self.db_session.commit()
        logger.info(f"Processed {processed_count} virtual networks")
        return processed_count

    def _process_s3_buckets(self, resources) -> int:
        """Process AWS S3 buckets."""
        if not resources:
            return 0

        # Get or create AWS provider and account
        provider = self._get_or_create_provider('aws')
        account_id = resources[0][0]
        account = self._get_or_create_account(provider.id, account_id)

        processed_count = 0
        for resource in resources:
            try:
                policy_status = resource[5] or {}
                # Check if bucket has public access based on policy status
                public_access = False
                if policy_status:
                    # If there's a policy, check if it allows public access
                    public_access = True  # Conservative assumption - would need to parse policy

                cloud_resource = CloudResource(
                    provider_id=provider.id,
                    account_id=account.id,
                    resource_id=resource[1] or '',  # arn
                    resource_arn=resource[1] or '',
                    resource_name=resource[2] or '',  # name
                    resource_type='s3_bucket',
                    service_name='s3',
                    region=resource[3] or 'us-east-1',
                    state='active',
                    configuration={
                        'creation_date': resource[4].isoformat() if resource[4] else None,
                        'policy_status': policy_status
                    },
                    tags=resource[6] or {},
                    public_access=public_access,
                    encryption_enabled=False,  # Would need to check bucket encryption separately
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow()
                )

                self.db_session.add(cloud_resource)
                processed_count += 1

            except Exception as e:
                logger.error(f"Error processing S3 bucket {resource[2]}: {e}")
                continue

        self.db_session.commit()
        logger.info(f"Processed {processed_count} S3 buckets")
        return processed_count

    def _process_iam_users(self, resources) -> int:
        """Process AWS IAM users."""
        if not resources:
            return 0

        provider = self._get_or_create_provider('aws')
        account_id = resources[0][0]
        account = self._get_or_create_account(provider.id, account_id)

        processed_count = 0
        for resource in resources:
            try:
                cloud_resource = CloudResource(
                    provider_id=provider.id,
                    account_id=account.id,
                    resource_id=resource[1] or '',  # arn
                    resource_arn=resource[1] or '',
                    resource_name=resource[2] or '',  # user_name
                    resource_type='iam_user',
                    service_name='iam',
                    region='global',
                    state='active',
                    configuration={
                        'create_date': resource[3].isoformat() if resource[3] else None,
                        'path': resource[4] or '/'
                    },
                    tags=resource[5] or {},
                    public_access=False,
                    encryption_enabled=True,
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow()
                )

                self.db_session.add(cloud_resource)
                processed_count += 1

            except Exception as e:
                logger.error(f"Error processing IAM user {resource[2]}: {e}")
                continue

        self.db_session.commit()
        logger.info(f"Processed {processed_count} IAM users")
        return processed_count

    def _process_ec2_instances(self, resources) -> int:
        """Process AWS EC2 instances."""
        if not resources:
            return 0

        provider = self._get_or_create_provider('aws')
        account_id = resources[0][0]
        account = self._get_or_create_account(provider.id, account_id)

        processed_count = 0
        for resource in resources:
            try:
                state_info = resource[4] or {}
                instance_state = state_info.get('name', 'unknown') if isinstance(
                    state_info, dict) else str(state_info)

                cloud_resource = CloudResource(
                    provider_id=provider.id,
                    account_id=account.id,
                    resource_id=resource[1] or '',  # arn
                    resource_arn=resource[1] or '',
                    resource_name=resource[2] or '',  # instance_id
                    resource_type='ec2_instance',
                    service_name='ec2',
                    region=resource[5] or 'unknown',
                    availability_zone=resource[6] or '',
                    vpc_id=resource[7] or '',
                    subnet_id=resource[8] or '',
                    state=instance_state,
                    configuration={
                        'instance_type': resource[3] or '',
                        'state': state_info
                    },
                    tags=resource[9] or {},
                    public_access=False,  # Would need to check security groups
                    encryption_enabled=False,  # Would need to check EBS encryption
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow()
                )

                self.db_session.add(cloud_resource)
                processed_count += 1

            except Exception as e:
                logger.error(
                    f"Error processing EC2 instance {resource[2]}: {e}")
                continue

        self.db_session.commit()
        logger.info(f"Processed {processed_count} EC2 instances")
        return processed_count

    def _get_or_create_provider(self, provider_name: str) -> CloudProvider:
        """Get or create cloud provider."""
        provider = self.db_session.query(CloudProvider).filter(
            CloudProvider.name == provider_name
        ).first()

        if not provider:
            provider = CloudProvider(
                name=provider_name,
                display_name=provider_name.upper(),
                api_version="latest",
                last_sync=datetime.utcnow(),
                sync_status="completed"
            )
            self.db_session.add(provider)
            self.db_session.commit()

        return provider

    def _get_or_create_account(self, provider_id: str, account_id: str) -> CloudAccount:
        """Get or create cloud account."""
        account = self.db_session.query(CloudAccount).filter(
            CloudAccount.provider_id == provider_id,
            CloudAccount.account_id == account_id
        ).first()

        if not account:
            account = CloudAccount(
                provider_id=provider_id,
                account_id=account_id,
                account_name=f"{account_id[:8]}...",
                environment="production",
                last_sync=datetime.utcnow(),
                sync_status="completed"
            )
            self.db_session.add(account)
            self.db_session.commit()

        return account

    def update_processing_status(self, queue_id: str, status: str, error_message: str = None):
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


def listen_for_notifications():
    """Listen for PostgreSQL notifications and process data."""
    conn = psycopg2.connect(DATABASE_URL)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

    cursor = conn.cursor()
    cursor.execute("LISTEN sync_complete;")

    processor = SimpleDataProcessor()

    logger.info(
        "Simple data processor started. Listening for sync notifications...")

    try:
        while True:
            if conn.poll() != psycopg2.extensions.POLL_OK:
                logger.error("Database connection lost. Reconnecting...")
                conn.close()
                conn = psycopg2.connect(DATABASE_URL)
                conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                cursor = conn.cursor()
                cursor.execute("LISTEN sync_complete;")
                processor = SimpleDataProcessor()

            # Check for notifications
            conn.poll()
            while conn.notifies:
                notify = conn.notifies.pop(0)
                logger.info(f"Received notification: {notify.payload}")

                try:
                    # Parse notification payload
                    payload = json.loads(notify.payload)
                    table_name = payload['table_name']
                    provider = payload['provider']

                    # Get pending processing jobs
                    queue_items = processor.db_session.execute(text("""
                        SELECT id, table_name, provider 
                        FROM sync_processing_queue 
                        WHERE status = 'pending' 
                        AND table_name = :table_name
                        ORDER BY created_at ASC
                        LIMIT 1
                    """), {'table_name': table_name}).fetchall()

                    for queue_item in queue_items:
                        queue_id, table_name, provider = queue_item

                        try:
                            # Update status to processing
                            processor.update_processing_status(
                                queue_id, 'processing')

                            # Process data based on provider
                            if provider == 'azure':
                                processed_count = processor.process_azure_data(
                                    table_name)
                            elif provider == 'aws':
                                processed_count = processor.process_aws_data(
                                    table_name)
                            elif provider == 'gcp':
                                processed_count = processor.process_gcp_data(
                                    table_name)
                            else:
                                logger.warning(f"Unknown provider: {provider}")
                                processed_count = 0

                            # Update status to completed
                            processor.update_processing_status(
                                queue_id, 'completed')
                            logger.info(
                                f"Successfully processed {processed_count} resources from {table_name}")

                        except Exception as e:
                            logger.error(f"Error processing {table_name}: {e}")
                            processor.update_processing_status(
                                queue_id, 'failed', str(e))

                except Exception as e:
                    logger.error(f"Error handling notification: {e}")

            # Small delay to prevent excessive CPU usage
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Data processor stopped by user")
    except Exception as e:
        logger.error(f"Data processor error: {e}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    listen_for_notifications()
