
from datetime import datetime
from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


AssetType = Literal[
    "SERVER",
    "ENDPOINT",
    "NETWORK_DEVICE",
    "CLOUD_RESOURCE",
    "APPLICATION",
    "DATABASE",
    "OTHER",
]

AssetCriticality = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
AssetStatus = Literal["ACTIVE", "INACTIVE", "UNDER_MAINTENANCE", "RETIRED"]


class AssetCreate(BaseModel):
    organization_id: int = Field(gt=0)
    asset_tag: str = Field(min_length=2, max_length=80)
    name: str = Field(min_length=2, max_length=150)
    asset_type: AssetType
    description: str | None = Field(default=None, max_length=5000)
    ip_address: str | None = None
    hostname: str | None = Field(default=None, max_length=255)
    operating_system: str | None = Field(default=None, max_length=150)
    owner_user_id: int | None = Field(default=None, gt=0)
    criticality: AssetCriticality = "MEDIUM"
    status: AssetStatus = "ACTIVE"
    location: str | None = Field(default=None, max_length=255)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value):
        if value is not None:
            try:
                ip_address(value)
            except ValueError as exc:
                raise ValueError("A valid IPv4 or IPv6 address is required.") from exc
        return value

    @field_validator("asset_tag")
    @classmethod
    def normalize_asset_tag(cls, value):
        return value.strip().upper()

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value):
        return value.strip()


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=150)
    asset_type: AssetType | None = None
    description: str | None = Field(default=None, max_length=5000)
    ip_address: str | None = None
    hostname: str | None = Field(default=None, max_length=255)
    operating_system: str | None = Field(default=None, max_length=150)
    owner_user_id: int | None = Field(default=None, gt=0)
    criticality: AssetCriticality | None = None
    status: AssetStatus | None = None
    location: str | None = Field(default=None, max_length=255)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value):
        if value is not None:
            try:
                ip_address(value)
            except ValueError as exc:
                raise ValueError("A valid IPv4 or IPv6 address is required.") from exc
        return value


class AssetResponse(BaseModel):
    id: int
    organization_id: int
    asset_tag: str
    name: str
    asset_type: str
    description: str | None
    ip_address: str | None
    hostname: str | None
    operating_system: str | None
    owner_user_id: int | None
    criticality: str
    status: str
    location: str | None
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
