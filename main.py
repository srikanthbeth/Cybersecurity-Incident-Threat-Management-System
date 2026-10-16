
from contextlib import asynccontextmanager

from fastapi import FastAPI

import models
from database import Base, engine
from routes.auth import router as auth_router
from routes.users import router as users_router
from routes.organizations import router as organizations_router
from routes.assets import router as assets_router
from routes.security_teams import router as security_teams_router
from routes.alerts import router as alerts_router
from routes.incidents import incidents_router
from routes.correlation import router as correlation_router
from routes.vulnerabilities import router as vulnerabilities_router
from routes.risk_assessments import router as risk_assessments_router
from routes.remediations import router as remediations_router
from routes.investigations import router as investigations_router
from routes.response_playbooks import router as response_playbooks_router
from routes.sla import router as sla_router
from routes.audit_logs import router as audit_logs_router
from routes.dashboard import router as dashboard_router
from routes.reports import router as reports_router
from routes.search import router as search_router



@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Cybersecurity Incident & Threat Management System",
    description=(
        "Backend API for cybersecurity alerts, incidents, "
        "vulnerabilities, risk, and response management."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(organizations_router)
app.include_router(assets_router)
app.include_router(security_teams_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(correlation_router)
app.include_router(vulnerabilities_router)
app.include_router(risk_assessments_router)
app.include_router(remediations_router)
app.include_router(investigations_router)
app.include_router(response_playbooks_router)
app.include_router(sla_router)
app.include_router(audit_logs_router)
app.include_router(dashboard_router)
app.include_router(reports_router)
app.include_router(search_router)



@app.get("/", tags=["Health"])
def root():
    return {
        "message": "Cybersecurity Incident & Threat Management API",
        "status": "running",
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy"}
