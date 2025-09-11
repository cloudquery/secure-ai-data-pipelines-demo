#!/usr/bin/env python3
"""
Simple Azure data processing script
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.models.database import Base
from app.models.cloud_resources import CloudProvider, CloudAccount, CloudResource
import sys
import os
from datetime import datetime
from typing import Dict, Any, List
import json

# Add the app directory to the Python path
sys.path.append('/app')


# Database connection - use environment variable
DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://cloudquery:secure_password@postgres:5432/cloudquery_security")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def main():
    """Main processing function."""
    print("Starting Azure CloudQuery data processing...")

    # Create database tables
    Base.metadata.create_all(bind=engine)
    print("Database tables created/verified")

    # Process data
    session = SessionLocal()

    try:
        # Get Azure resources from CloudQuery tables
        print("Fetching Azure resources from CloudQuery tables...")

        # Get virtual machines
        vms = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                vm_size,
                provisioning_state,
                tags,
                created_at
            FROM azure_compute_virtual_machines
            LIMIT 20
        """)).fetchall()

        # Get storage accounts
        storage_accounts = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                allow_blob_public_access,
                tags,
                created_at
            FROM azure_storage_accounts
            LIMIT 20
        """)).fetchall()

        # Get SQL servers
        sql_servers = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                public_network_access,
                tags,
                created_at
            FROM azure_sql_servers
            LIMIT 20
        """)).fetchall()

        print(f"Found {len(vms)} virtual machines")
        print(f"Found {len(storage_accounts)} storage accounts")
        print(f"Found {len(sql_servers)} SQL servers")

        # Create Azure provider
        print("Creating Azure provider...")
        provider = session.query(CloudProvider).filter(
            CloudProvider.name == "azure").first()
        if not provider:
            provider = CloudProvider(
                name="azure",
                display_name="Microsoft Azure",
                api_version="v10.0.0",
                last_sync=datetime.utcnow(),
                sync_status="completed"
            )
            session.add(provider)
            session.commit()
        print(f"Azure provider ID: {provider.id}")

        # Get subscription ID from first resource
        subscription_id = None
        if vms:
            subscription_id = vms[0][0]
        elif storage_accounts:
            subscription_id = storage_accounts[0][0]
        elif sql_servers:
            subscription_id = sql_servers[0][0]

        if not subscription_id:
            print("No subscription ID found in Azure CloudQuery data")
            return

        # Create Azure account
        print(
            f"Creating Azure account for subscription: {subscription_id[:8]}...")
        account = session.query(CloudAccount).filter(
            CloudAccount.provider_id == provider.id,
            CloudAccount.account_id == subscription_id
        ).first()
        if not account:
            account = CloudAccount(
                provider_id=provider.id,
                account_id=subscription_id,
                account_name=f"Azure Subscription {subscription_id[:8]}...",
                environment="production",
                last_sync=datetime.utcnow(),
                sync_status="completed"
            )
            session.add(account)
            session.commit()
        print(f"Azure account ID: {account.id}")

        # Process resources
        total_created = 0

        print("Processing virtual machines...")
        vm_count = 0
        for vm in vms:
            resource = CloudResource(
                provider_id=provider.id,
                account_id=account.id,
                resource_id=vm[1] or '',
                resource_name=vm[2] or '',
                resource_type='virtual_machine',
                service_name='compute',
                region=vm[3] or 'unknown',
                state=vm[5] or 'unknown',
                configuration={
                    'vm_size': vm[4],
                    'resource_group': vm[4],
                    'provisioning_state': vm[5]
                },
                tags=vm[7] or {},
                public_access=False,  # Simplified - would need network analysis
                encryption_enabled=True,
                resource_created_at=vm[8],
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow()
            )
            session.add(resource)
            vm_count += 1
        print(f"Created {vm_count} virtual machine resources")
        total_created += vm_count

        print("Processing storage accounts...")
        storage_count = 0
        for st in storage_accounts:
            resource = CloudResource(
                provider_id=provider.id,
                account_id=account.id,
                resource_id=st[1] or '',
                resource_name=st[2] or '',
                resource_type='storage_account',
                service_name='storage',
                region=st[3] or 'unknown',
                state='active',
                configuration={
                    'resource_group': st[4],
                    'allow_blob_public_access': st[5]
                },
                tags=st[6] or {},
                public_access=st[5] or False,
                encryption_enabled=True,
                resource_created_at=st[7],
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow()
            )
            session.add(resource)
            storage_count += 1
        print(f"Created {storage_count} storage account resources")
        total_created += storage_count

        print("Processing SQL servers...")
        sql_count = 0
        for sql in sql_servers:
            resource = CloudResource(
                provider_id=provider.id,
                account_id=account.id,
                resource_id=sql[1] or '',
                resource_name=sql[2] or '',
                resource_type='sql_server',
                service_name='sql',
                region=sql[3] or 'unknown',
                state='active',
                configuration={
                    'resource_group': sql[4],
                    'public_network_access': sql[5]
                },
                tags=sql[6] or {},
                public_access=sql[5] == 'Enabled' if sql[5] else False,
                encryption_enabled=True,
                resource_created_at=sql[7],
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow()
            )
            session.add(resource)
            sql_count += 1
        print(f"Created {sql_count} SQL server resources")
        total_created += sql_count

        # Commit all changes
        session.commit()

        print(f"\n✅ Successfully processed {total_created} Azure resources!")
        print("Azure data is now available in the backend API")

    except Exception as e:
        print(f"❌ Error processing Azure data: {e}")
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
