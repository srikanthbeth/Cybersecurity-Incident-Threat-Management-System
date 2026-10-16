
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from core.dependencies import get_current_user
from database import get_db
from services.search_service import SearchService

router = APIRouter(
    prefix="/api/v1/search",
    tags=["Advanced Search"],
)


def _run_search(
    db: Session,
    *,
    q: str | None,
    severity: str | None,
    status: str | None,
    asset_id: int | None,
    analyst_id: int | None,
    organization_name: str | None,
    incident_number: str | None,
    start_date: date | None,
    end_date: date | None,
    page: int,
    page_size: int,
    sort_by: str,
    sort_order: str,
):
    try:
        return SearchService(db).search(
            q=q,
            severity=severity,
            status=status,
            asset_id=asset_id,
            analyst_id=analyst_id,
            organization_name=organization_name,
            incident_number=incident_number,
            start_date=start_date,
            end_date=end_date,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_order=sort_order,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/", summary="Search incidents and alerts")
def search_incidents_and_alerts(
    q: str | None = Query(default=None, description="Search text"),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    asset_id: int | None = Query(default=None, gt=0),
    analyst_id: int | None = Query(default=None, gt=0),
    organization_name: str | None = Query(default=None),
    incident_number: str | None = Query(default=None),
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort_by: str = Query(
        default="created_at",
        pattern="^(created_at|severity|status|title|reference)$",
    ),
    sort_order: str = Query(
        default="desc",
        pattern="^(asc|desc)$",
    ),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _run_search(
        db,
        q=q,
        severity=severity,
        status=status,
        asset_id=asset_id,
        analyst_id=analyst_id,
        organization_name=organization_name,
        incident_number=incident_number,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get(
    "/incidents/reference/{incident_number}",
    summary="Search incidents by reference number",
)
def search_by_incident_reference(
    incident_number: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _run_search(
        db,
        q=None,
        severity=None,
        status=None,
        asset_id=None,
        analyst_id=None,
        organization_name=None,
        incident_number=incident_number,
        start_date=None,
        end_date=None,
        page=page,
        page_size=page_size,
        sort_by="created_at",
        sort_order="desc",
    )
