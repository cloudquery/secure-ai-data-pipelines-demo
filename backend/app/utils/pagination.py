"""
Pagination utilities for API endpoints.
"""
from typing import Dict, Any
from sqlalchemy.orm import Query
import math


def paginate(query: Query, page: int, size: int) -> Dict[str, Any]:
    """
    Paginate a SQLAlchemy query.

    Args:
        query: SQLAlchemy query object
        page: Page number (1-based)
        size: Number of items per page

    Returns:
        Dictionary with paginated results and metadata
    """

    # Get total count
    total = query.count()

    # Calculate pagination metadata
    pages = math.ceil(total / size) if total > 0 else 1
    offset = (page - 1) * size

    # Get items for current page
    items = query.offset(offset).limit(size).all()

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": pages,
        "has_next": page < pages,
        "has_prev": page > 1
    }
