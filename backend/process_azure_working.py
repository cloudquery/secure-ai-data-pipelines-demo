#!/usr/bin/env python3
"""
Working Azure data processing script - processes resources with correct schema
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

        # Get storage accounts (has data and correct schema)
        storage_accounts = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                properties,
                tags
            FROM azure_storage_accounts
            LIMIT 20
        """)).fetchall()

        # Get network security groups (has data and correct schema)
        nsgs = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                properties,
                tags
            FROM azure_network_security_groups
            LIMIT 20
        """)).fetchall()

        # Get virtual networks (has data and correct schema)
        vnets = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                properties,
                tags
            FROM azure_network_virtual_networks
            LIMIT 20
        """)).fetchall()

        # Get public IP addresses (has data and correct schema)
        public_ips = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                properties,
                tags
            FROM azure_network_public_ip_addresses
            LIMIT 20
        """)).fetchall()

        # Get network interfaces (has data and correct schema)
        nics = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                properties,
                tags
            FROM azure_network_interfaces
            LIMIT 20
        """)).fetchall()

        print(f"Found {len(storage_accounts)} storage accounts")
        print(f"Found {len(nsgs)} network security groups")
        print(f"Found {len(vnets)} virtual networks")
        print(f"Found {len(public_ips)} public IP addresses")
        print(f"Found {len(nics)} network interfaces")

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
        for resource_list in [storage_accounts, nsgs, vnets, public_ips, nics]:
            if resource_list:
                subscription_id = resource_list[0][0]
                break

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

        print("Processing storage accounts...")
        storage_count = 0
        for st in storage_accounts:
            # Extract properties for configuration
            properties = st[4] or {}
            if isinstance(properties, dict):
                allow_blob_public_access = properties.get(
                    'allowBlobPublicAccess', False)
                https_traffic_only = properties.get(
                    'supportsHttpsTrafficOnly', True)
            else:
                allow_blob_public_access = False
                https_traffic_only = True

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
                    'properties': properties,
                    'allow_blob_public_access': allow_blob_public_access,
                    'https_traffic_only': https_traffic_only
                },
                tags=st[5] or {},
                public_access=allow_blob_public_access,
                encryption_enabled=True,
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow()
            )
            session.add(resource)
            storage_count += 1
        print(f"Created {storage_count} storage account resources")
        total_created += storage_count

        print("Processing network security groups...")
        nsg_count = 0
        for nsg in nsgs:
            properties = nsg[4] or {}
            resource = CloudResource(
                provider_id=provider.id,
                account_id=account.id,
                resource_id=nsg[1] or '',
                resource_name=nsg[2] or '',
                resource_type='network_security_group',
                service_name='network',
                region=nsg[3] or 'unknown',
                state='active',
                configuration={'properties': properties},
                tags=nsg[5] or {},
                public_access=False,
                encryption_enabled=False,
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow()
            )
            session.add(resource)
            nsg_count += 1
        print(f"Created {nsg_count} NSG resources")
        total_created += nsg_count

        print("Processing virtual networks...")
        vnet_count = 0
        for vnet in vnets:
            properties = vnet[4] or {}
            resource = CloudResource(
                provider_id=provider.id,
                account_id=account.id,
                resource_id=vnet[1] or '',
                resource_name=vnet[2] or '',
                resource_type='virtual_network',
                service_name='network',
                region=vnet[3] or 'unknown',
                state='active',
                configuration={'properties': properties},
                tags=vnet[5] or {},
                public_access=False,
                encryption_enabled=False,
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow()
            )
            session.add(resource)
            vnet_count += 1
        print(f"Created {vnet_count} virtual network resources")
        total_created += vnet_count

        print("Processing public IP addresses...")
        ip_count = 0
        for ip in public_ips:
            properties = ip[4] or {}
            # Check if IP is public (simplified)
            public_access = True  # Public IPs are inherently public

            resource = CloudResource(
                provider_id=provider.id,
                account_id=account.id,
                resource_id=ip[1] or '',
                resource_name=ip[2] or '',
                resource_type='public_ip_address',
                service_name='network',
                region=ip[3] or 'unknown',
                state='active',
                configuration={'properties': properties},
                tags=ip[5] or {},
                public_access=public_access,
                encryption_enabled=False,
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow()
            )
            session.add(resource)
            ip_count += 1
        print(f"Created {ip_count} public IP resources")
        total_created += ip_count

        print("Processing network interfaces...")
        nic_count = 0
        for nic in nics:
            properties = nic[4] or {}
            resource = CloudResource(
                provider_id=provider.id,
                account_id=account.id,
                resource_id=nic[1] or '',
                resource_name=nic[2] or '',
                resource_type='network_interface',
                service_name='network',
                region=nic[3] or 'unknown',
                state='active',
                configuration={'properties': properties},
                tags=nic[5] or {},
                public_access=False,
                encryption_enabled=False,
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow()
            )
            session.add(resource)
            nic_count += 1
        print(f"Created {nic_count} network interface resources")
        total_created += nic_count

        # Commit all changes
        session.commit()

        print(f"\n✅ Successfully processed {total_created} Azure resources!")
        print("Azure data is now available in the backend API")
        print(f"Resource breakdown:")
        print(f"  - Storage Accounts: {storage_count}")
        print(f"  - Network Security Groups: {nsg_count}")
        print(f"  - Virtual Networks: {vnet_count}")
        print(f"  - Public IP Addresses: {ip_count}")
        print(f"  - Network Interfaces: {nic_count}")

    except Exception as e:
        print(f"❌ Error processing Azure data: {e}")
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
