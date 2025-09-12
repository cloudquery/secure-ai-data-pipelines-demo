#!/usr/bin/env python3
"""
Comprehensive background data processor for automatic CloudQuery sync processing.
Processes ALL resources from CloudQuery tables, not just recent ones.
"""

import logging
import time
from typing import Dict, Any
from sqlalchemy import text

from app.workers.base_processor import BaseDataProcessor

logger = logging.getLogger(__name__)


class ComprehensiveDataProcessor(BaseDataProcessor):
    """Comprehensive background processor for CloudQuery sync data."""

    def __init__(self):
        super().__init__()

    def process_all_resources(self) -> Dict[str, int]:
        """Process all resources from CloudQuery tables."""
        results = {}

        # Process AWS resources
        aws_results = self.process_aws_resources()
        results.update(aws_results)

        # Process Azure resources
        azure_results = self.process_azure_resources()
        results.update(azure_results)

        # Process GCP resources
        gcp_results = self.process_gcp_resources()
        results.update(gcp_results)

        return results

    def process_aws_resources(self) -> Dict[str, int]:
        """Process all AWS resources from CloudQuery tables."""
        logger.info("Processing AWS resources...")
        results = {}

        # Get AWS provider
        aws_provider = self._get_or_create_provider('aws')

        # Process S3 buckets
        results['aws_s3_buckets'] = self._process_aws_s3_buckets(aws_provider)

        # Process EC2 instances
        results['aws_ec2_instances'] = self._process_aws_ec2_instances(
            aws_provider)

        # Process IAM users
        results['aws_iam_users'] = self._process_aws_iam_users(aws_provider)

        # Process IAM roles
        results['aws_iam_roles'] = self._process_aws_iam_roles(aws_provider)

        # Process RDS instances
        results['aws_rds_instances'] = self._process_aws_rds_instances(
            aws_provider)

        # Process Lambda functions
        results['aws_lambda_functions'] = self._process_aws_lambda_functions(
            aws_provider)

        # Process VPCs
        results['aws_vpcs'] = self._process_aws_vpcs(aws_provider)

        # Process Security Groups
        results['aws_security_groups'] = self._process_aws_security_groups(
            aws_provider)

        return results

    def process_azure_resources(self) -> Dict[str, int]:
        """Process all Azure resources from CloudQuery tables."""
        logger.info("Processing Azure resources...")
        results = {}

        # Get Azure provider
        azure_provider = self._get_or_create_provider('azure')

        # Process Storage Accounts
        results['azure_storage_accounts'] = self._process_azure_storage_accounts(
            azure_provider)

        # Process Virtual Machines
        results['azure_virtual_machines'] = self._process_azure_virtual_machines(
            azure_provider)

        # Process Network Security Groups
        results['azure_network_security_groups'] = self._process_azure_network_security_groups(
            azure_provider)

        # Process Virtual Networks
        results['azure_virtual_networks'] = self._process_azure_virtual_networks(
            azure_provider)

        # Process SQL Servers
        results['azure_sql_servers'] = self._process_azure_sql_servers(
            azure_provider)

        return results

    def process_gcp_resources(self) -> Dict[str, int]:
        """Process all GCP resources from CloudQuery tables."""
        logger.info("Processing GCP resources...")
        results = {}

        # Get GCP provider
        gcp_provider = self._get_or_create_provider('gcp')

        # Process Compute Instances
        results['gcp_compute_instances'] = self._process_gcp_compute_instances(
            gcp_provider)

        # Process Storage Buckets
        results['gcp_storage_buckets'] = self._process_gcp_storage_buckets(
            gcp_provider)

        return results

    def _process_aws_s3_buckets(self, provider: CloudProvider) -> int:
        """Process AWS S3 buckets."""
        try:
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
                ORDER BY name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            account_id = resources[0][0]
            account = self._get_or_create_account(provider.id, account_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # arn
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    policy_status = resource[5] or {}
                    # Conservative assumption
                    public_access = bool(policy_status)

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
                        encryption_enabled=False,  # Would need separate check
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(
                        f"Error processing S3 bucket {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} S3 buckets")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing S3 buckets: {e}")
            return 0

    def _process_aws_ec2_instances(self, provider: CloudProvider) -> int:
        """Process AWS EC2 instances."""
        try:
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
                ORDER BY instance_id
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            account_id = resources[0][0]
            account = self._get_or_create_account(provider.id, account_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # arn
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

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
                        public_access=False,  # Would need security group check
                        encryption_enabled=False,  # Would need EBS check
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

        except Exception as e:
            logger.error(f"Error processing EC2 instances: {e}")
            return 0

    def _process_aws_iam_users(self, provider: CloudProvider) -> int:
        """Process AWS IAM users."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    account_id,
                    arn,
                    user_name,
                    create_date,
                    path,
                    tags
                FROM aws_iam_users
                ORDER BY user_name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            account_id = resources[0][0]
            account = self._get_or_create_account(provider.id, account_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # arn
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

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
                    logger.error(
                        f"Error processing IAM user {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} IAM users")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing IAM users: {e}")
            return 0

    def _process_aws_iam_roles(self, provider: CloudProvider) -> int:
        """Process AWS IAM roles."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    account_id,
                    arn,
                    role_name,
                    create_date,
                    path,
                    tags
                FROM aws_iam_roles
                ORDER BY role_name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            account_id = resources[0][0]
            account = self._get_or_create_account(provider.id, account_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # arn
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=resource[1] or '',  # arn
                        resource_arn=resource[1] or '',
                        resource_name=resource[2] or '',  # role_name
                        resource_type='iam_role',
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
                    logger.error(
                        f"Error processing IAM role {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} IAM roles")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing IAM roles: {e}")
            return 0

    def _process_aws_rds_instances(self, provider: CloudProvider) -> int:
        """Process AWS RDS instances."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    account_id,
                    arn,
                    db_instance_identifier,
                    db_instance_class,
                    db_instance_status,
                    availability_zone,
                    vpc_id,
                    subnet_group_name,
                    tags
                FROM aws_rds_instances
                ORDER BY db_instance_identifier
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            account_id = resources[0][0]
            account = self._get_or_create_account(provider.id, account_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # arn
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=resource[1] or '',  # arn
                        resource_arn=resource[1] or '',
                        # db_instance_identifier
                        resource_name=resource[2] or '',
                        resource_type='rds_instance',
                        service_name='rds',
                        region='unknown',  # Would need to extract from ARN
                        availability_zone=resource[5] or '',
                        vpc_id=resource[6] or '',
                        state=resource[4] or 'unknown',  # db_instance_status
                        configuration={
                            'db_instance_class': resource[3] or '',
                            'subnet_group_name': resource[7] or ''
                        },
                        tags=resource[8] or {},
                        public_access=False,  # Would need separate check
                        encryption_enabled=False,  # Would need separate check
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(
                        f"Error processing RDS instance {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} RDS instances")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing RDS instances: {e}")
            return 0

    def _process_aws_lambda_functions(self, provider: CloudProvider) -> int:
        """Process AWS Lambda functions."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    account_id,
                    arn,
                    function_name,
                    runtime,
                    state,
                    region,
                    vpc_config,
                    tags
                FROM aws_lambda_functions
                ORDER BY function_name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            account_id = resources[0][0]
            account = self._get_or_create_account(provider.id, account_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # arn
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=resource[1] or '',  # arn
                        resource_arn=resource[1] or '',
                        resource_name=resource[2] or '',  # function_name
                        resource_type='lambda_function',
                        service_name='lambda',
                        region=resource[5] or 'unknown',
                        state=resource[4] or 'unknown',
                        configuration={
                            'runtime': resource[3] or '',
                            'vpc_config': resource[6] or {}
                        },
                        tags=resource[7] or {},
                        public_access=False,  # Would need separate check
                        encryption_enabled=True,  # Lambda functions are encrypted by default
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(
                        f"Error processing Lambda function {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} Lambda functions")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing Lambda functions: {e}")
            return 0

    def _process_aws_vpcs(self, provider: CloudProvider) -> int:
        """Process AWS VPCs."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    account_id,
                    arn,
                    vpc_id,
                    state,
                    region,
                    cidr_block,
                    tags
                FROM aws_vpcs
                ORDER BY vpc_id
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            account_id = resources[0][0]
            account = self._get_or_create_account(provider.id, account_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # arn
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=resource[1] or '',  # arn
                        resource_arn=resource[1] or '',
                        resource_name=resource[2] or '',  # vpc_id
                        resource_type='vpc',
                        service_name='ec2',
                        region=resource[4] or 'unknown',
                        state=resource[3] or 'unknown',
                        configuration={
                            'cidr_block': resource[5] or ''
                        },
                        tags=resource[6] or {},
                        public_access=False,
                        encryption_enabled=False,
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(f"Error processing VPC {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} VPCs")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing VPCs: {e}")
            return 0

    def _process_aws_security_groups(self, provider: CloudProvider) -> int:
        """Process AWS Security Groups."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    account_id,
                    arn,
                    group_id,
                    group_name,
                    description,
                    region,
                    vpc_id,
                    tags
                FROM aws_security_groups
                ORDER BY group_id
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            account_id = resources[0][0]
            account = self._get_or_create_account(provider.id, account_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # arn
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=resource[1] or '',  # arn
                        resource_arn=resource[1] or '',
                        resource_name=resource[2] or '',  # group_id
                        resource_type='security_group',
                        service_name='ec2',
                        region=resource[5] or 'unknown',
                        vpc_id=resource[6] or '',
                        state='active',
                        configuration={
                            'group_name': resource[3] or '',
                            'description': resource[4] or ''
                        },
                        tags=resource[7] or {},
                        public_access=False,  # Would need to check rules
                        encryption_enabled=False,
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(
                        f"Error processing Security Group {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} Security Groups")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing Security Groups: {e}")
            return 0

    def _process_azure_storage_accounts(self, provider: CloudProvider) -> int:
        """Process Azure storage accounts."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    subscription_id,
                    id,
                    name,
                    location,
                    properties,
                    tags
                FROM azure_storage_accounts
                ORDER BY name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            subscription_id = resources[0][0]
            account = self._get_or_create_account(provider.id, subscription_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # id
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

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
                        f"Error processing storage account {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} storage accounts")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing storage accounts: {e}")
            return 0

    def _process_azure_virtual_machines(self, provider: CloudProvider) -> int:
        """Process Azure virtual machines."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    subscription_id,
                    id,
                    name,
                    location,
                    properties,
                    tags
                FROM azure_compute_virtual_machines
                ORDER BY name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            subscription_id = resources[0][0]
            account = self._get_or_create_account(provider.id, subscription_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # id
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    properties = resource[4] or {}

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=resource[1] or '',
                        resource_name=resource[2] or '',
                        resource_type='virtual_machine',
                        service_name='compute',
                        region=resource[3] or 'unknown',
                        state='active',
                        configuration={'properties': properties},
                        tags=resource[5] or {},
                        public_access=False,  # Would need separate check
                        encryption_enabled=False,  # Would need separate check
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(
                        f"Error processing virtual machine {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} virtual machines")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing virtual machines: {e}")
            return 0

    def _process_azure_network_security_groups(self, provider: CloudProvider) -> int:
        """Process Azure network security groups."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    subscription_id,
                    id,
                    name,
                    location,
                    properties,
                    tags
                FROM azure_network_security_groups
                ORDER BY name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            subscription_id = resources[0][0]
            account = self._get_or_create_account(provider.id, subscription_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # id
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

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
                    logger.error(f"Error processing NSG {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} network security groups")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing network security groups: {e}")
            return 0

    def _process_azure_virtual_networks(self, provider: CloudProvider) -> int:
        """Process Azure virtual networks."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    subscription_id,
                    id,
                    name,
                    location,
                    properties,
                    tags
                FROM azure_network_virtual_networks
                ORDER BY name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            subscription_id = resources[0][0]
            account = self._get_or_create_account(provider.id, subscription_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # id
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

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
                    logger.error(f"Error processing VNet {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} virtual networks")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing virtual networks: {e}")
            return 0

    def _process_azure_sql_servers(self, provider: CloudProvider) -> int:
        """Process Azure SQL servers."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    subscription_id,
                    id,
                    name,
                    location,
                    properties,
                    tags
                FROM azure_sql_servers
                ORDER BY name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            subscription_id = resources[0][0]
            account = self._get_or_create_account(provider.id, subscription_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == resource[1],  # id
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    properties = resource[4] or {}

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=resource[1] or '',
                        resource_name=resource[2] or '',
                        resource_type='sql_server',
                        service_name='sql',
                        region=resource[3] or 'unknown',
                        state='active',
                        configuration={'properties': properties},
                        tags=resource[5] or {},
                        public_access=False,  # Would need separate check
                        encryption_enabled=True,  # Azure SQL is encrypted by default
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(
                        f"Error processing SQL server {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} SQL servers")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing SQL servers: {e}")
            return 0

    def _process_gcp_compute_instances(self, provider: CloudProvider) -> int:
        """Process GCP compute instances."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    project_id,
                    id,
                    name,
                    zone,
                    machine_type,
                    status,
                    tags
                FROM gcp_compute_instances
                ORDER BY name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            project_id = resources[0][0]
            account = self._get_or_create_account(provider.id, project_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == str(resource[1]),  # id
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=str(resource[1]) or '',
                        resource_name=resource[2] or '',
                        resource_type='compute_instance',
                        service_name='compute',
                        region=resource[3].split('-')[0] + '-' + resource[3].split(
                            # Extract region from zone
                            '-')[1] if resource[3] else 'unknown',
                        availability_zone=resource[3] or '',
                        state=resource[5] or 'unknown',
                        configuration={
                            'machine_type': resource[4] or ''
                        },
                        tags=resource[6] or {},
                        public_access=False,  # Would need separate check
                        encryption_enabled=True,  # GCP instances are encrypted by default
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(
                        f"Error processing compute instance {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} compute instances")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing compute instances: {e}")
            return 0

    def _process_gcp_storage_buckets(self, provider: CloudProvider) -> int:
        """Process GCP storage buckets."""
        try:
            resources = self.db_session.execute(text("""
                SELECT 
                    project_id,
                    id,
                    name,
                    location,
                    storage_class,
                    tags
                FROM gcp_storage_buckets
                ORDER BY name
            """)).fetchall()

            if not resources:
                return 0

            # Get or create account
            project_id = resources[0][0]
            account = self._get_or_create_account(provider.id, project_id)

            processed_count = 0
            for resource in resources:
                try:
                    # Check if resource already exists
                    existing = self.db_session.query(CloudResource).filter(
                        CloudResource.resource_id == str(resource[1]),  # id
                        CloudResource.provider_id == provider.id
                    ).first()

                    if existing:
                        continue

                    cloud_resource = CloudResource(
                        provider_id=provider.id,
                        account_id=account.id,
                        resource_id=str(resource[1]) or '',
                        resource_name=resource[2] or '',
                        resource_type='storage_bucket',
                        service_name='storage',
                        region=resource[3] or 'unknown',
                        state='active',
                        configuration={
                            'storage_class': resource[4] or ''
                        },
                        tags=resource[5] or {},
                        public_access=False,  # Would need separate check
                        encryption_enabled=True,  # GCP storage is encrypted by default
                        discovered_at=datetime.utcnow(),
                        last_scanned=datetime.utcnow()
                    )

                    self.db_session.add(cloud_resource)
                    processed_count += 1

                except Exception as e:
                    logger.error(
                        f"Error processing storage bucket {resource[2]}: {e}")
                    continue

            self.db_session.commit()
            logger.info(f"Processed {processed_count} storage buckets")
            return processed_count

        except Exception as e:
            logger.error(f"Error processing storage buckets: {e}")
            return 0

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


def run_comprehensive_processing():
    """Run comprehensive processing of all CloudQuery resources."""
    processor = ComprehensiveDataProcessor()

    logger.info("Starting comprehensive resource processing...")

    try:
        results = processor.process_all_resources()

        total_processed = sum(results.values())
        logger.info(f"Comprehensive processing completed!")
        logger.info(f"Results: {results}")
        logger.info(f"Total resources processed: {total_processed}")

        return results

    except Exception as e:
        logger.error(f"Error during comprehensive processing: {e}")
        raise


if __name__ == "__main__":
    run_comprehensive_processing()
