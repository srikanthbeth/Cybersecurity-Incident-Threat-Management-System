
from datetime import date

from sqlalchemy.orm import Session

from repositories.search_repository import SearchRepository


class SearchService:
    ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def __init__(self, db: Session):
        self.repository = SearchRepository(db)

    def search(
        self,
        *,
        q: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        asset_id: int | None = None,
        analyst_id: int | None = None,
        organization_name: str | None = None,
        incident_number: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> dict:
        if start_date and end_date and start_date > end_date:
            raise ValueError(
                "start_date must be on or before end_date"
            )

        if severity and severity.upper() not in self.ALLOWED_SEVERITIES:
            raise ValueError(
                "severity must be LOW, MEDIUM, HIGH, or CRITICAL"
            )

        if page < 1:
            raise ValueError("page must be at least 1")

        if not 1 <= page_size <= 100:
            raise ValueError("page_size must be between 1 and 100")

        if sort_by not in {
            "created_at", "severity", "status", "title", "reference"
        }:
            raise ValueError("Unsupported sort_by field")

        if sort_order not in {"asc", "desc"}:
            raise ValueError("sort_order must be asc or desc")

        results = self.repository.search(
            q=q,
            severity=severity,
            status=status,
            asset_id=asset_id,
            analyst_id=analyst_id,
            organization_name=organization_name,
            incident_number=incident_number,
            start_date=start_date,
            end_date=end_date,
        )

        def sort_key(item):
            value = item.get(sort_by)
            if sort_by == "created_at":
                return value.isoformat() if value else ""
            return str(value or "").casefold()

        results.sort(key=sort_key, reverse=(sort_order == "desc"))

        total = len(results)
        start_index = (page - 1) * page_size
        paginated_results = results[start_index:start_index + page_size]

        # Return JSON-serializable timestamps.
        for item in paginated_results:
            if item["created_at"] is not None:
                item["created_at"] = item["created_at"].isoformat()

        return {
            "items": paginated_results,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": (total + page_size - 1) // page_size,
                "has_next": start_index + page_size < total,
                "has_previous": page > 1,
            },
            "filters": {
                "q": q,
                "severity": severity,
                "status": status,
                "asset_id": asset_id,
                "analyst_id": analyst_id,
                "organization_name": organization_name,
                "incident_number": incident_number,
                "start_date": str(start_date) if start_date else None,
                "end_date": str(end_date) if end_date else None,
                "sort_by": sort_by,
                "sort_order": sort_order,
            },
        }
