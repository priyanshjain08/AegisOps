import uuid
from datetime import datetime, timezone
from sqlalchemy import (String, Text, Integer, Float, Boolean, DateTime, ForeignKey, UniqueConstraint, Index, BigInteger)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.db import Base

def now(): return datetime.now(timezone.utc)
def pk(): return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
def fk(t, **kw): return mapped_column(UUID(as_uuid=True), ForeignKey(t, ondelete="CASCADE"), **kw)
def ts(**kw): return mapped_column(DateTime(timezone=True), default=now, **kw)

class Organization(Base):
    __tablename__ = "organizations"
    id = pk(); name: Mapped[str] = mapped_column(String(200)); is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at = ts(); updated_at = ts(onupdate=now)

class User(Base):
    __tablename__ = "users"
    id = pk(); email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255)); full_name: Mapped[str] = mapped_column(String(200), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True); created_at = ts(); updated_at = ts(onupdate=now)

class OrganizationMember(Base):
    __tablename__ = "organization_members"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)
    id = pk(); organization_id = fk("organizations.id", index=True); user_id = fk("users.id", index=True)
    role: Mapped[str] = mapped_column(String(32))  # owner | security_admin | analyst | viewer
    created_at = ts()

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = pk(); user_id = fk("users.id", index=True); org_id = fk("organizations.id")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at = ts(); revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True); created_at = ts()

class Asset(Base):
    __tablename__ = "assets"
    id = pk(); organization_id = fk("organizations.id", index=True)
    name: Mapped[str] = mapped_column(String(200)); hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45)); os: Mapped[str | None] = mapped_column(String(100))
    asset_type: Mapped[str] = mapped_column(String(32), default="other"); environment: Mapped[str] = mapped_column(String(32), default="production")
    owner: Mapped[str | None] = mapped_column(String(200)); criticality: Mapped[str] = mapped_column(String(16), default="medium")
    tags: Mapped[list] = mapped_column(JSONB, default=list); last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    monitoring_status: Mapped[str] = mapped_column(String(32), default="no_data_source")
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False); created_at = ts(); updated_at = ts(onupdate=now)

class LogSource(Base):
    __tablename__ = "log_sources"
    id = pk(); organization_id = fk("organizations.id", index=True); name: Mapped[str] = mapped_column(String(200))
    source_type: Mapped[str] = mapped_column(String(64), default="generic")
    api_key_hash: Mapped[str | None] = mapped_column(String(64), unique=True)  # for REST agent ingestion
    created_at = ts()

class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    id = pk(); organization_id = fk("organizations.id", index=True); source_id = fk("log_sources.id", nullable=True)
    filename: Mapped[str | None] = mapped_column(String(255)); fmt: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|processing|completed|failed
    total: Mapped[int] = mapped_column(Integer, default=0); accepted: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0); errors: Mapped[list] = mapped_column(JSONB, default=list)
    created_at = ts(); finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (UniqueConstraint("organization_id", "dedup_hash"),
                      Index("ix_events_org_ts", "organization_id", "timestamp"),
                      Index("ix_events_org_srcip", "organization_id", "source_ip"))
    id = pk(); organization_id = fk("organizations.id"); source_id = fk("log_sources.id", nullable=True)
    job_id = fk("ingestion_jobs.id", nullable=True)
    timestamp = mapped_column(DateTime(timezone=True)); source_type: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(255)); username: Mapped[str | None] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(String(45)); destination_ip: Mapped[str | None] = mapped_column(String(45))
    category: Mapped[str] = mapped_column(String(64)); action: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16)); result: Mapped[str | None] = mapped_column(String(32))
    raw: Mapped[dict] = mapped_column(JSONB); attributes: Mapped[dict] = mapped_column(JSONB, default=dict)
    dedup_hash: Mapped[str] = mapped_column(String(64)); is_simulated: Mapped[bool] = mapped_column(Boolean, default=False)

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (UniqueConstraint("organization_id", "rule_key"),)
    id = pk(); organization_id = fk("organizations.id", index=True); rule_key: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(200)); description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64)); severity: Mapped[str] = mapped_column(String(16))
    thresholds: Mapped[dict] = mapped_column(JSONB); enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1); last_executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class DetectionRuleExecution(Base):
    __tablename__ = "detection_rule_executions"
    id = pk(); organization_id = fk("organizations.id", index=True); rule_id = fk("detection_rules.id", index=True)
    started_at = ts(); events_evaluated: Mapped[int] = mapped_column(Integer, default=0); findings: Mapped[int] = mapped_column(Integer, default=0)

class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_org_status", "organization_id", "status"),)
    id = pk(); organization_id = fk("organizations.id"); rule_id = fk("detection_rules.id", nullable=True)
    title: Mapped[str] = mapped_column(String(300)); description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16)); score: Mapped[int] = mapped_column(Integer); category: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float); status: Mapped[str] = mapped_column(String(24), default="new")
    entities: Mapped[dict] = mapped_column(JSONB, default=dict); event_ids: Mapped[list] = mapped_column(JSONB, default=list)
    assigned_to = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    incident_id = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False); created_at = ts(); updated_at = ts(onupdate=now)

class Incident(Base):
    __tablename__ = "incidents"
    id = pk(); organization_id = fk("organizations.id", index=True); title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default=""); severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="open")
    assigned_to = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    affected_assets: Mapped[list] = mapped_column(JSONB, default=list); is_simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at = ts(); updated_at = ts(onupdate=now)

class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    incident_id = fk("incidents.id", primary_key=True); alert_id = fk("alerts.id", primary_key=True)

class IncidentEvent(Base):
    __tablename__ = "incident_events"
    incident_id = fk("incidents.id", primary_key=True); event_id = fk("security_events.id", primary_key=True)

class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    id = pk(); organization_id = fk("organizations.id", index=True); incident_id = fk("incidents.id", index=True)
    author_id = mapped_column(UUID(as_uuid=True), ForeignKey("users.id")); body: Mapped[str] = mapped_column(Text); created_at = ts()

class AIAnalysis(Base):
    __tablename__ = "ai_analyses"
    id = pk(); organization_id = fk("organizations.id", index=True); incident_id = fk("incidents.id", index=True)
    version: Mapped[int] = mapped_column(Integer); provider: Mapped[str] = mapped_column(String(32)); model: Mapped[str | None] = mapped_column(String(100))
    is_llm: Mapped[bool] = mapped_column(Boolean); content: Mapped[dict] = mapped_column(JSONB)
    requested_by = mapped_column(UUID(as_uuid=True), ForeignKey("users.id")); created_at = ts()  # previous versions are kept

class ResponseAction(Base):
    __tablename__ = "response_actions"
    id = pk(); organization_id = fk("organizations.id", index=True); incident_id = fk("incidents.id", nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(48)); params: Mapped[dict] = mapped_column(JSONB)
    requested_by = mapped_column(UUID(as_uuid=True), ForeignKey("users.id")); origin: Mapped[str] = mapped_column(String(8), default="human")
    approval_status: Mapped[str] = mapped_column(String(24), default="pending_approval")
    execution_status: Mapped[str] = mapped_column(String(24), default="not_executed"); result: Mapped[dict | None] = mapped_column(JSONB)
    created_at = ts(); updated_at = ts(onupdate=now)

class ResponseApproval(Base):
    __tablename__ = "response_approvals"
    id = pk(); organization_id = fk("organizations.id", index=True); action_id = fk("response_actions.id", index=True)
    approver_id = mapped_column(UUID(as_uuid=True), ForeignKey("users.id")); approved: Mapped[bool] = mapped_column(Boolean)
    comment: Mapped[str | None] = mapped_column(Text); created_at = ts()

class ResponseExecution(Base):
    __tablename__ = "response_executions"
    id = pk(); organization_id = fk("organizations.id", index=True); action_id = fk("response_actions.id", index=True)
    status: Mapped[str] = mapped_column(String(16)); result: Mapped[dict] = mapped_column(JSONB); created_at = ts()

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = pk(); organization_id = mapped_column(UUID(as_uuid=True), index=True, nullable=True)
    actor_id = mapped_column(UUID(as_uuid=True), nullable=True); action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64)); resource_id: Mapped[str | None] = mapped_column(String(64))
    meta: Mapped[dict] = mapped_column(JSONB, default=dict); request_id: Mapped[str | None] = mapped_column(String(64)); created_at = ts(index=True)

class Integration(Base):
    __tablename__ = "integrations"
    id = pk(); organization_id = fk("organizations.id", index=True); kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(200)); config: Mapped[dict] = mapped_column(JSONB, default=dict)  # secrets never returned by API
    enabled: Mapped[bool] = mapped_column(Boolean, default=True); created_at = ts()

class Notification(Base):
    __tablename__ = "notifications"
    id = pk(); organization_id = fk("organizations.id", index=True); user_id = mapped_column(UUID(as_uuid=True), nullable=True)
    title: Mapped[str] = mapped_column(String(300)); body: Mapped[str] = mapped_column(Text, default="")
    read: Mapped[bool] = mapped_column(Boolean, default=False); created_at = ts()
