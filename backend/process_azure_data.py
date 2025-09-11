#!/usr/bin/env python3
"""
Script to process Azure CloudQuery data and populate the backend's normalized schema.
This script reads data from Azure CloudQuery tables and creates normalized cloud resources.
"""

import sys
import os
from datetime import datetime
from typing import Dict, Any, List
import json

# Add the backend directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from app.models.cloud_resources import CloudProvider, CloudAccount, CloudResource
from app.models.database import Base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, text

# Database connection
DATABASE_URL = "postgresql://cloudquery:secure_password@postgres:5432/cloudquery_security"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_azure_resources():
    """Get Azure resources from CloudQuery tables."""
    session = SessionLocal()

    try:
        # Get virtual machines
        virtual_machines = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                vm_size,
                os_disk,
                data_disks,
                network_profile,
                storage_profile,
                hardware_profile,
                provisioning_state,
                tags,
                created_at,
                updated_at
            FROM azure_compute_virtual_machines
            LIMIT 50
        """)).fetchall()

        # Get storage accounts
        storage_accounts = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                sku,
                kind,
                access_tier,
                enable_https_traffic_only,
                allow_blob_public_access,
                network_rule_set,
                encryption,
                tags,
                created_at,
                updated_at
            FROM azure_storage_accounts
            LIMIT 50
        """)).fetchall()

        # Get SQL servers
        sql_servers = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                version,
                administrator_login,
                public_network_access,
                minimal_tls_version,
                state,
                tags,
                created_at,
                updated_at
            FROM azure_sql_servers
            LIMIT 50
        """)).fetchall()

        # Get Key Vaults
        key_vaults = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                vault_uri,
                tenant_id,
                sku,
                access_policies,
                enabled_for_disk_encryption,
                enabled_for_template_deployment,
                enable_soft_delete,
                soft_delete_retention_in_days,
                enable_purge_protection,
                tags,
                created_at,
                updated_at
            FROM azure_keyvault_keyvault
            LIMIT 50
        """)).fetchall()

        # Get Network Security Groups
        nsgs = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                security_rules,
                default_security_rules,
                tags,
                created_at,
                updated_at
            FROM azure_network_security_groups
            LIMIT 50
        """)).fetchall()

        # Get Web Apps
        web_apps = session.execute(text("""
            SELECT 
                subscription_id,
                id,
                name,
                location,
                resource_group,
                kind,
                state,
                host_names,
                enabled,
                https_only,
                client_affinity_enabled,
                client_cert_enabled,
                client_cert_mode,
                tags,
                created_at,
                updated_at
            FROM azure_appservice_web_apps
            LIMIT 50
        """)).fetchall()

        return {
            'virtual_machines': [dict(row._mapping) for row in virtual_machines],
            'storage_accounts': [dict(row._mapping) for row in storage_accounts],
            'sql_servers': [dict(row._mapping) for row in sql_servers],
            'key_vaults': [dict(row._mapping) for row in key_vaults],
            'nsgs': [dict(row._mapping) for row in nsgs],
            'web_apps': [dict(row._mapping) for row in web_apps]
        }

    finally:
        session.close()


def create_azure_provider(session):
    """Create Azure provider record."""
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
    return provider


def create_azure_account(session, provider_id, subscription_id):
    """Create Azure account record."""
    account = session.query(CloudAccount).filter(
        CloudAccount.provider_id == provider_id,
        CloudAccount.account_id == subscription_id
    ).first()
    if not account:
        account = CloudAccount(
            provider_id=provider_id,
            account_id=subscription_id,
            account_name=f"Azure Subscription {subscription_id[:8]}...",
            environment="production",
            last_sync=datetime.utcnow(),
            sync_status="completed"
        )
        session.add(account)
        session.commit()
    return account


def process_virtual_machines(session, provider_id, account_id, vms):
    """Process virtual machines and create cloud resources."""
    resources_created = 0

    for vm in vms:
        # Extract region from location
        location = vm.get('location', '')
        region = location if location else 'unknown'

        # Create resource configuration
        configuration = {
            'vm_size': vm.get('vm_size'),
            'os_disk': vm.get('os_disk'),
            'data_disks': vm.get('data_disks'),
            'network_profile': vm.get('network_profile'),
            'storage_profile': vm.get('storage_profile'),
            'hardware_profile': vm.get('hardware_profile'),
            'provisioning_state': vm.get('provisioning_state'),
            'resource_group': vm.get('resource_group')
        }

        # Determine if VM has public access (simplified check)
        public_access = False
        network_profile = vm.get('network_profile', {})
        if isinstance(network_profile, dict):
            network_interfaces = network_profile.get('network_interfaces', [])
            for ni in network_interfaces:
                if isinstance(ni, dict) and ni.get('id'):
                    # Check if the network interface has public IP
                    public_access = True
                    break

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=vm.get('id', ''),
            resource_name=vm.get('name', ''),
            resource_type='virtual_machine',
            service_name='compute',
            region=region,
            state=vm.get('provisioning_state', 'unknown'),
            configuration=configuration,
            tags=vm.get('tags', {}),
            public_access=public_access,
            encryption_enabled=True,  # Azure VMs are encrypted by default
            resource_created_at=vm.get('created_at'),
            last_modified=vm.get('updated_at'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def process_storage_accounts(session, provider_id, account_id, accounts):
    """Process storage accounts and create cloud resources."""
    resources_created = 0

    for account in accounts:
        # Check if storage account allows public access
        public_access = account.get('allow_blob_public_access', False)

        # Check encryption
        encryption_enabled = True
        encryption_config = account.get('encryption', {})
        if isinstance(encryption_config, dict):
            encryption_enabled = encryption_config.get('services', {}).get('blob', {}).get('enabled', True)

        configuration = {
            'sku': account.get('sku'),
            'kind': account.get('kind'),
            'access_tier': account.get('access_tier'),
            'enable_https_traffic_only': account.get('enable_https_traffic_only'),
            'allow_blob_public_access': account.get('allow_blob_public_access'),
            'network_rule_set': account.get('network_rule_set'),
            'encryption': account.get('encryption'),
            'resource_group': account.get('resource_group')
        }

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=account.get('id', ''),
            resource_name=account.get('name', ''),
            resource_type='storage_account',
            service_name='storage',
            region=account.get('location', 'unknown'),
            state='active',
            configuration=configuration,
            tags=account.get('tags', {}),
            public_access=public_access,
            encryption_enabled=encryption_enabled,
            resource_created_at=account.get('created_at'),
            last_modified=account.get('updated_at'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def process_sql_servers(session, provider_id, account_id, servers):
    """Process SQL servers and create cloud resources."""
    resources_created = 0

    for server in servers:
        # Check if SQL server allows public access
        public_access = server.get('public_network_access', 'Disabled') == 'Enabled'

        configuration = {
            'version': server.get('version'),
            'administrator_login': server.get('administrator_login'),
            'public_network_access': server.get('public_network_access'),
            'minimal_tls_version': server.get('minimal_tls_version'),
            'state': server.get('state'),
            'resource_group': server.get('resource_group')
        }

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=server.get('id', ''),
            resource_name=server.get('name', ''),
            resource_type='sql_server',
            service_name='sql',
            region=server.get('location', 'unknown'),
            state=server.get('state', 'unknown'),
            configuration=configuration,
            tags=server.get('tags', {}),
            public_access=public_access,
            encryption_enabled=True,  # Azure SQL servers are encrypted by default
            resource_created_at=server.get('created_at'),
            last_modified=server.get('updated_at'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def process_key_vaults(session, provider_id, account_id, vaults):
    """Process Key Vaults and create cloud resources."""
    resources_created = 0

    for vault in vaults:
        # Key Vaults are not public by default
        public_access = False

        # Check if soft delete is enabled
        encryption_enabled = True  # Key Vaults are encrypted by default

        configuration = {
            'vault_uri': vault.get('vault_uri'),
            'tenant_id': vault.get('tenant_id'),
            'sku': vault.get('sku'),
            'access_policies': vault.get('access_policies'),
            'enabled_for_disk_encryption': vault.get('enabled_for_disk_encryption'),
            'enabled_for_template_deployment': vault.get('enabled_for_template_deployment'),
            'enable_soft_delete': vault.get('enable_soft_delete'),
            'soft_delete_retention_in_days': vault.get('soft_delete_retention_in_days'),
            'enable_purge_protection': vault.get('enable_purge_protection'),
            'resource_group': vault.get('resource_group')
        }

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=vault.get('id', ''),
            resource_name=vault.get('name', ''),
            resource_type='key_vault',
            service_name='keyvault',
            region=vault.get('location', 'unknown'),
            state='active',
            configuration=configuration,
            tags=vault.get('tags', {}),
            public_access=public_access,
            encryption_enabled=encryption_enabled,
            resource_created_at=vault.get('created_at'),
            last_modified=vault.get('updated_at'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def process_network_security_groups(session, provider_id, account_id, nsgs):
    """Process Network Security Groups and create cloud resources."""
    resources_created = 0

    for nsg in nsgs:
        # NSGs are not public resources themselves
        public_access = False

        configuration = {
            'security_rules': nsg.get('security_rules'),
            'default_security_rules': nsg.get('default_security_rules'),
            'resource_group': nsg.get('resource_group')
        }

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=nsg.get('id', ''),
            resource_name=nsg.get('name', ''),
            resource_type='network_security_group',
            service_name='network',
            region=nsg.get('location', 'unknown'),
            state='active',
            configuration=configuration,
            tags=nsg.get('tags', {}),
            public_access=public_access,
            encryption_enabled=False,  # NSGs don't store encrypted data
            resource_created_at=nsg.get('created_at'),
            last_modified=nsg.get('updated_at'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def process_web_apps(session, provider_id, account_id, apps):
    """Process Web Apps and create cloud resources."""
    resources_created = 0

    for app in apps:
        # Check if web app is publicly accessible
        public_access = True  # Web apps are typically public by default
        if app.get('enabled') == False:
            public_access = False

        configuration = {
            'kind': app.get('kind'),
            'state': app.get('state'),
            'host_names': app.get('host_names'),
            'enabled': app.get('enabled'),
            'https_only': app.get('https_only'),
            'client_affinity_enabled': app.get('client_affinity_enabled'),
            'client_cert_enabled': app.get('client_cert_enabled'),
            'client_cert_mode': app.get('client_cert_mode'),
            'resource_group': app.get('resource_group')
        }

        resource = CloudResource(
            provider_id=provider_id,
            account_id=account_id,
            resource_id=app.get('id', ''),
            resource_name=app.get('name', ''),
            resource_type='web_app',
            service_name='appservice',
            region=app.get('location', 'unknown'),
            state=app.get('state', 'unknown'),
            configuration=configuration,
            tags=app.get('tags', {}),
            public_access=public_access,
            encryption_enabled=True,  # Web apps support encryption
            resource_created_at=app.get('created_at'),
            last_modified=app.get('updated_at'),
            discovered_at=datetime.utcnow(),
            last_scanned=datetime.utcnow()
        )

        session.add(resource)
        resources_created += 1

    return resources_created


def main():
    """Main processing function."""
    print("Starting Azure CloudQuery data processing...")

    # Create database tables
    Base.metadata.create_all(bind=engine)
    print("Database tables created/verified")

    # Get Azure resources from CloudQuery tables
    print("Fetching Azure resources from CloudQuery tables...")
    azure_data = get_azure_resources()

    print(f"Found {len(azure_data['virtual_machines'])} virtual machines")
    print(f"Found {len(azure_data['storage_accounts'])} storage accounts")
    print(f"Found {len(azure_data['sql_servers'])} SQL servers")
    print(f"Found {len(azure_data['key_vaults'])} Key Vaults")
    print(f"Found {len(azure_data['nsgs'])} Network Security Groups")
    print(f"Found {len(azure_data['web_apps'])} Web Apps")

    # Process data
    session = SessionLocal()

    try:
        # Create Azure provider
        print("Creating Azure provider...")
        provider = create_azure_provider(session)
        print(f"Azure provider ID: {provider.id}")

        # Get subscription ID from first resource
        subscription_id = None
        for resource_type, resources in azure_data.items():
            if resources:
                subscription_id = resources[0].get('subscription_id')
                break

        if not subscription_id:
            print("No subscription ID found in Azure CloudQuery data")
            return

        # Create Azure account
        print(f"Creating Azure account for subscription: {subscription_id[:8]}...")
        account = create_azure_account(session, provider.id, subscription_id)
        print(f"Azure account ID: {account.id}")

        # Process resources
        total_created = 0

        print("Processing virtual machines...")
        vms_created = process_virtual_machines(
            session, provider.id, account.id, azure_data['virtual_machines'])
        print(f"Created {vms_created} virtual machine resources")
        total_created += vms_created

        print("Processing storage accounts...")
        storage_created = process_storage_accounts(
            session, provider.id, account.id, azure_data['storage_accounts'])
        print(f"Created {storage_created} storage account resources")
        total_created += storage_created

        print("Processing SQL servers...")
        sql_created = process_sql_servers(
            session, provider.id, account.id, azure_data['sql_servers'])
        print(f"Created {sql_created} SQL server resources")
        total_created += sql_created

        print("Processing Key Vaults...")
        kv_created = process_key_vaults(
            session, provider.id, account.id, azure_data['key_vaults'])
        print(f"Created {kv_created} Key Vault resources")
        total_created += kv_created

        print("Processing Network Security Groups...")
        nsg_created = process_network_security_groups(
            session, provider.id, account.id, azure_data['nsgs'])
        print(f"Created {nsg_created} NSG resources")
        total_created += nsg_created

        print("Processing Web Apps...")
        webapp_created = process_web_apps(
            session, provider.id, account.id, azure_data['web_apps'])
        print(f"Created {webapp_created} Web App resources")
        total_created += webapp_created

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
