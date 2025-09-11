#!/usr/bin/env python3
"""
Script to process CloudQuery data and populate the backend's normalized schema.
This script reads data from CloudQuery tables and creates normalized cloud resources.
"""

from app.models.cloud_resources import CloudProvider, CloudAccount, CloudResource
from app.models.database import Base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, text
import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, List
import uuid

# Add the backend directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))


# Database connection
DATABASE_URL = "postgresql://cloudquery:secure_password@postgres:5432/cloudquery_security"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_gcp_resources():
    """Get GCP resources from CloudQuery tables."""
    session = SessionLocal()

    try:
        # Get compute instances
        compute_instances = session.execute(text("""
            SELECT 
                project_id,
                name,
                id,
                machine_type,
                status,
                zone,
                labels,
                tags,
                creation_timestamp,
                last_start_timestamp,
                last_stop_timestamp,
                metadata
            FROM gcp_compute_instances
            LIMIT 10
        """)).fetchall()

        # Get storage buckets
        storage_buckets = session.execute(text("""
            SELECT 
                project_id,
                name,
                id,
                location,
                storage_class,
                labels,
                created,
                updated,
                iam_configuration,
                cors,
                lifecycle
            FROM gcp_storage_buckets
            LIMIT 10
        """)).fetchall()

        # Get IAM service accounts
        service_accounts = session.execute(text("""
            SELECT 
                project_id,
                unique_id,
                email,
                display_name,
                description,
                disabled,
                created_at,
                updated_at
            FROM gcp_iam_service_accounts
            LIMIT 10
        """)).fetchall()

        return {
            'compute_instances': [dict(row._mapping) for row in compute_instances],
            'storage_buckets': [dict(row._mapping) for row in storage_buckets],
            'service_accounts': [dict(row._mapping) for row in service_accounts]
        }

    finally:
        session.close()


def create_gcp_provider(session):
    """Create GCP provider record."""
    provider = session.query(CloudProvider).filter(
        CloudProvider.name == "gcp").first()
    if not provider:
        provider = CloudProvider(
            name="gcp",
            display_name="Google Cloud Platform",
            api_version="v13.0.0",
            last_sync=datetime.utcnow(),
            sync_status="completed"
        )
        session.add(provider)
        session.commit()
    return provider


def create_gcp_account(session, provider_id, project_id):
    """Create GCP account record."""
    account = session.query(CloudAccount).filter(
        CloudAccount.provider_id == provider_id,
        CloudAccount.account_id == project_id
    ).first()
    if not account:
        account = CloudAccount(
            provider_id=provider_id,
            account_id=project_id,
            account_name=f"GCP Project {project_id}",
            environment="production",
            last_sync=datetime.utcnow(),
            sync_status="completed"
        )
        session.add(account)
        session.commit()
    return account


def process_compute_instances(session, provider_id, account_id, instances):
    """Process compute instances and create cloud resources."""
    resources_created = 0

    for instance in instances:
        # Extract region from zone
        zone = instance.get('zone', '')
        region = zone.rsplit('-', 1)[0] if zone else 'unknown'

        # Create resource configuration
        configuration = {
            'machine_type': instance.get('machine_type'),
            'status': instance.get('status'),
            'zone': zone,
            'labels': instance.get('labels', {}),
            'tags': instance.get('tags', []),
            'creation_timestamp': instance.get('creation_timestamp'),
            'metadata': instance.get('metadata', {})
        }

        # Determine if instance is public (simplified check)
        public_access = False
        if instance.get('metadata'):
            metadata = instance.get('metadata', {})
            if isinstance(metadata, dict):
                items = metadata.get('items', [])
                for item in items:
                    if item.get('key') == 'enable-oslogin' and item.get('value') == 'TRUE':
                        public_access = True
                        break

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=instance.get('id', instance.get('name', '')),
            resource_name=instance.get('name', ''),
            resource_type='compute_instance',
            service_name='compute',
            region=region,
            availability_zone=zone,
            state=instance.get('status', 'unknown'),
            configuration=configuration,
            tags=instance.get('labels', {}),
            public_access=public_access,
            encryption_enabled=True,  # GCP instances are encrypted by default
            resource_created_at=instance.get('creation_timestamp'),
            last_modified=instance.get('last_stop_timestamp') or instance.get(
                'last_start_timestamp'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def process_storage_buckets(session, provider_id, account_id, buckets):
    """Process storage buckets and create cloud resources."""
    resources_created = 0

    for bucket in buckets:
        # Check if bucket is public
        public_access = False
        iam_config = bucket.get('iam_configuration', {})
        if isinstance(iam_config, dict):
            public_access = iam_config.get(
                'public_access_prevention') == 'inherited'

        # Check encryption
        encryption_enabled = True  # GCP buckets are encrypted by default

        configuration = {
            'location': bucket.get('location'),
            'storage_class': bucket.get('storage_class'),
            'labels': bucket.get('labels', {}),
            'created': bucket.get('created'),
            'updated': bucket.get('updated'),
            'cors': bucket.get('cors', []),
            'lifecycle': bucket.get('lifecycle', {})
        }

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=bucket.get('id', bucket.get('name', '')),
            resource_name=bucket.get('name', ''),
            resource_type='storage_bucket',
            service_name='storage',
            region=bucket.get('location', 'unknown'),
            state='active',
            configuration=configuration,
            tags=bucket.get('labels', {}),
            public_access=public_access,
            encryption_enabled=encryption_enabled,
            resource_created_at=bucket.get('created'),
            last_modified=bucket.get('updated'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def process_service_accounts(session, provider_id, account_id, accounts):
    """Process service accounts and create cloud resources."""
    resources_created = 0

    for sa in accounts:
        configuration = {
            'unique_id': sa.get('unique_id'),
            'email': sa.get('email'),
            'display_name': sa.get('display_name'),
            'description': sa.get('description'),
            'disabled': sa.get('disabled', False),
            'created_at': sa.get('created_at'),
            'updated_at': sa.get('updated_at')
        }

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=sa.get('unique_id', sa.get('email', '')),
            resource_name=sa.get('email', ''),
            resource_type='service_account',
            service_name='iam',
            state='active' if not sa.get('disabled', False) else 'disabled',
            configuration=configuration,
            public_access=False,  # Service accounts are not public
            encryption_enabled=True,
            resource_created_at=sa.get('created_at'),
            last_modified=sa.get('updated_at'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def main():
    """Main processing function."""
    print("Starting CloudQuery data processing...")

    # Create database tables
    Base.metadata.create_all(bind=engine)
    print("Database tables created/verified")

    # Get GCP resources from CloudQuery tables
    print("Fetching GCP resources from CloudQuery tables...")
    gcp_data = get_gcp_resources()

    print(f"Found {len(gcp_data['compute_instances'])} compute instances")
    print(f"Found {len(gcp_data['storage_buckets'])} storage buckets")
    print(f"Found {len(gcp_data['service_accounts'])} service accounts")

    # Process data
    session = SessionLocal()

    try:
        # Create GCP provider
        print("Creating GCP provider...")
        provider = create_gcp_provider(session)
        print(f"GCP provider ID: {provider.id}")

        # Get project ID from first resource
        project_id = None
        if gcp_data['compute_instances']:
            project_id = gcp_data['compute_instances'][0]['project_id']
        elif gcp_data['storage_buckets']:
            project_id = gcp_data['storage_buckets'][0]['project_id']
        elif gcp_data['service_accounts']:
            project_id = gcp_data['service_accounts'][0]['project_id']

        if not project_id:
            print("No project ID found in CloudQuery data")
            return

        # Create GCP account
        print(f"Creating GCP account for project: {project_id}")
        account = create_gcp_account(session, provider.id, project_id)
        print(f"GCP account ID: {account.id}")

        # Process resources
        print("Processing compute instances...")
        instances_created = process_compute_instances(
            session, provider.id, account.id, gcp_data['compute_instances'])
        print(f"Created {instances_created} compute instance resources")

        print("Processing storage buckets...")
        buckets_created = process_storage_buckets(
            session, provider.id, account.id, gcp_data['storage_buckets'])
        print(f"Created {buckets_created} storage bucket resources")

        print("Processing service accounts...")
        accounts_created = process_service_accounts(
            session, provider.id, account.id, gcp_data['service_accounts'])
        print(f"Created {accounts_created} service account resources")

        # Commit all changes
        session.commit()

        total_created = instances_created + buckets_created + accounts_created
        print(f"\n✅ Successfully processed {total_created} GCP resources!")
        print("Data is now available in the backend API")

    except Exception as e:
        print(f"❌ Error processing data: {e}")
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
