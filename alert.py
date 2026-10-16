
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class AlertCategory(str, Enum):
    MALWARE = "MALWARE"
    PHISHING = "PHISHING"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    NETWORK_INTRUSION = "NETWORK_INTRUSION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    VULNERABILITY = "VULNERABILITY"
    OTHER = "OTHER"


class AlertCreate(BaseModel):
    external_alert_id: str | None = Field(default=None, min_length=1, max_length=150)
    source: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    category: AlertCategory = AlertCategory.OTHER
    severity: AlertSeverity = AlertSeverity.MEDIUM
    organization_id: int | None = Field(default=None, gt=0)
    asset_id: int | None = Field(default=None, gt=0)
    assigned_to: int | None = Field(default=None, gt=0)
    detected_at: datetime | None = None

    @model_validator(mode="after")
    def normalize_fields(self):
        self.source = self.source.strip()
        self.title = self.title.strip()

        if len(self.source) < 2:
            raise ValueError("Source must contain at least 2 characters.")
        if len(self.title) < 3:
            raise ValueError("Title must contain at least 3 characters.")

        if self.external_alert_id is not None:
            self.external_alert_id = self.external_alert_id.strip()
            if not self.external_alert_id:
                raise ValueError("External alert ID cannot be blank.")

        return self


class AlertUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    category: AlertCategory | None = None
    severity: AlertSeverity | None = None
    status: AlertStatus | None = None
    assigned_to: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_title(self):
        if self.title is not None:
            self.title = self.title.strip()
            if len(self.title) < 3:
                raise ValueError("Title must contain at least 3 characters.")
        return self


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    external_alert_id: str | None
    source: str
    title: str
    description: str | None
    category: str
    severity: str
    status: str
    organization_id: int | None
    asset_id: int | None
    assigned_to: int | None
    created_by: int | None
    detected_at: datetime
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime
