from typing import Literal
from pydantic import BaseModel, EmailStr, Field

class RegisterIn(BaseModel):
    email: EmailStr; password: str = Field(min_length=12, max_length=128); full_name: str = ""; organization_name: str = Field(min_length=2, max_length=200)
class LoginIn(BaseModel):
    email: EmailStr; password: str
class RefreshIn(BaseModel):
    refresh_token: str
class AssetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200); hostname: str | None = None; ip_address: str | None = None; os: str | None = None
    asset_type: Literal["server", "workstation", "laptop", "network_device", "cloud_resource", "application", "other"] = "other"
    environment: str = "production"; owner: str | None = None; criticality: Literal["low", "medium", "high", "critical"] = "medium"; tags: list[str] = []
class AlertPatch(BaseModel):
    status: Literal["new", "acknowledged", "investigating", "resolved", "false_positive"] | None = None
    assigned_to: str | None = None
class IncidentPatch(BaseModel):
    status: Literal["open", "investigating", "contained", "resolved", "closed"] | None = None
    assigned_to: str | None = None; title: str | None = None
class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=10000)
class RulePatch(BaseModel):
    enabled: bool | None = None; thresholds: dict | None = None
class ActionIn(BaseModel):
    action_type: str; params: dict = {}; incident_id: str | None = None
class DecisionIn(BaseModel):
    approve: bool; comment: str | None = None
class MemberRolePatch(BaseModel):
    role: Literal["owner", "security_admin", "analyst", "viewer"]
