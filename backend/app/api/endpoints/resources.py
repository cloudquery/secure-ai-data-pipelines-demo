"""
API endpoints for cloud resource management.
"""
from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc

from ...models import get_db, CloudResource, CloudProvider, CloudAccount, SecurityFinding
from ...core.security import mask_sensitive_fields
from ...utils.pagination import paginate

router = APIRouter(prefix="/resources", tags=["resources"])


@router.get("/test")
async def test_endpoint():
    """Test endpoint to verify the router is working."""
    return {"message": "Resources router is working", "status": "ok"}


@router.get("/test-db")
async def test_db_endpoint(db: Session = Depends(get_db)):
    """Test endpoint to verify database connection works."""
    try:
        count = db.query(CloudResource).count()
        return {
            "message": "Database connection successful",
            "resource_count": count,
            "status": "ok"
        }
    except Exception as e:
        return {
            "message": "Database connection failed",
            "error": str(e),
            "status": "error"
        }


@router.get("/stats/overview", response_model=Dict[str, Any])
async def get_resource_overview(
    db: Session = Depends(get_db)
):
    """Get overview statistics for cloud resources."""

    # Total resources by provider
    provider_stats = db.query(
        CloudProvider.name,
        CloudProvider.display_name,
        func.count(CloudResource.id).label("count")
    ).join(CloudResource).group_by(CloudProvider.id, CloudProvider.name, CloudProvider.display_name).all()

    # Resource types distribution
    type_stats = db.query(
        CloudResource.resource_type,
        func.count(CloudResource.id).label("count")
    ).group_by(CloudResource.resource_type).order_by(desc(func.count(CloudResource.id))).limit(10).all()

    # Security statistics
    security_stats = db.query(
        SecurityFinding.severity,
        func.count(SecurityFinding.id).label("count")
    ).group_by(SecurityFinding.severity).all()

    # Public access resources
    public_resources = db.query(func.count(CloudResource.id)).filter(
        CloudResource.public_access == True
    ).scalar()

    # Unencrypted resources
    unencrypted_resources = db.query(func.count(CloudResource.id)).filter(
        CloudResource.encryption_enabled == False
    ).scalar()

    # Total resources
    total_resources = db.query(func.count(CloudResource.id)).scalar()

    return {
        "total_resources": total_resources,
        "public_resources": public_resources,
        "unencrypted_resources": unencrypted_resources,
        "providers": [
            {
                "name": stat.name,
                "display_name": stat.display_name,
                "count": stat.count
            }
            for stat in provider_stats
        ],
        "resource_types": [
            {
                "type": stat.resource_type,
                "count": stat.count
            }
            for stat in type_stats
        ],
        "security_findings": [
            {
                "severity": stat.severity,
                "count": stat.count
            }
            for stat in security_stats
        ]
    }
