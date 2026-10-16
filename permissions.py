
from core.dependencies import require_roles


def require_sensitive_incident_access():
    return require_roles(
        "SUPER_ADMIN",
        "SECURITY_MANAGER",
        "INCIDENT_RESPONDER",
    )
