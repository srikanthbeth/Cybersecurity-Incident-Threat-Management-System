from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

from core.config import settings
from database import Base

# Import all models so Alembic can detect their tables.
from models.user import User
from models.auth_token import RevokedToken, PasswordResetToken
from models.organization import Organization
from models.asset import Asset
from models.security_team import SecurityTeam, SecurityTeamMember
from models.alert import Alert
from models.vulnerability import Vulnerability
from models.vulnerability_asset import VulnerabilityAsset
from models.vulnerability_history import VulnerabilityHistory
from models.risk_assessment import RiskAssessment
from models.risk_assessment_history import RiskAssessmentHistory
from models.remediation_task import RemediationTask
from models.remediation_evidence import RemediationEvidence
from models.remediation_history import RemediationHistory
from models.response_playbook import ResponsePlaybook
from models.response_playbook_step import ResponsePlaybookStep
from models.playbook_execution import PlaybookExecution
from models.playbook_execution_step import PlaybookExecutionStep
from models.response_history import ResponseHistory
from models.sla_policy import SLAPolicy
from models.incident_sla import IncidentSLA
from models.audit_log import AuditLog


# Alembic Config object
config = context.config


# Use DATABASE_URL from .env
config.set_main_option(
    "sqlalchemy.url",
    settings.DATABASE_URL.replace("%", "%%"),
)


# Configure Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# SQLAlchemy metadata used by Alembic autogenerate
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """
    Run migrations in offline mode.
    """

    url = settings.DATABASE_URL

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={
            "paramstyle": "named"
        },
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in online mode.
    """

    connectable = engine_from_config(
        config.get_section(
            config.config_ini_section,
            {}
        ),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()