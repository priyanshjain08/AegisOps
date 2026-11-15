"""Controlled response subsystem. Only allowlisted, validated, human-approved actions run.
The firewall adapter is a simulation: it never touches a real firewall or shell."""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Internal ranges are never blockable. Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)
# are allowed because demo data uses them and the adapter is simulated.
_NEVER_BLOCK = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                  "fc00::/7", "240.0.0.0/4")]

ALLOWED_ACTIONS = {
    "acknowledge_alert", "assign_incident", "add_note", "disable_detection_rule",
    "generate_report", "create_recommendation", "block_ip_simulated",
}
# Roles permitted to approve / request
APPROVER_ROLES = {"owner", "security_admin"}
REQUESTER_ROLES = {"owner", "security_admin", "analyst"}
PENDING, APPROVED, REJECTED, EXECUTED, FAILED, CANCELLED = (
    "pending_approval", "approved", "rejected", "executed", "failed", "cancelled")

class ResponseError(Exception):
    pass

def validate_params(action_type: str, params: dict) -> dict:
    if action_type not in ALLOWED_ACTIONS:
        raise ResponseError(f"action type {action_type!r} is not allowlisted")
    if not isinstance(params, dict):
        raise ResponseError("params must be an object")
    if action_type == "block_ip_simulated":
        try:
            ip = ipaddress.ip_address(str(params.get("ip", "")))
        except ValueError as e:
            raise ResponseError("valid 'ip' parameter required") from e
        if any(ip in n for n in _NEVER_BLOCK) or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ResponseError("refusing to block internal/loopback/reserved address")
        return {"ip": str(ip)}
    if action_type in ("acknowledge_alert",):
        if not params.get("alert_id"):
            raise ResponseError("alert_id required")
        return {"alert_id": str(params["alert_id"])}
    if action_type == "assign_incident":
        if not params.get("incident_id") or not params.get("user_id"):
            raise ResponseError("incident_id and user_id required")
        return {"incident_id": str(params["incident_id"]), "user_id": str(params["user_id"])}
    if action_type == "add_note":
        note = str(params.get("note", "")).strip()
        if not note or len(note) > 5000:
            raise ResponseError("note required (max 5000 chars)")
        return {"note": note}
    if action_type == "disable_detection_rule":
        if not params.get("rule_id"):
            raise ResponseError("rule_id required")
        return {"rule_id": str(params["rule_id"])}
    return {k: v for k, v in params.items() if isinstance(v, (str, int, float, bool))}

class MockFirewall:
    """Simulated adapter; records blocks in memory only."""
    simulated = True
    def __init__(self):
        self.blocked: set[str] = set()
    def block(self, ip: str) -> dict:
        already = ip in self.blocked
        self.blocked.add(ip)
        return {"simulated": True, "ip": ip, "changed": not already,
                "message": f"SIMULATED: {ip} added to mock firewall blocklist (no real firewall modified)"}

@dataclass
class ResponseAction:
    id: str
    organization_id: str
    incident_id: str | None
    action_type: str
    params: dict
    requested_by: str
    approval_status: str = PENDING
    execution_status: str = "not_executed"
    approved_by: str | None = None
    result: dict | None = None
    origin: str = "human"   # "human" | "ai" -- AI-origin actions still need approval
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    history: list[dict] = field(default_factory=list)

    def _log(self, event, actor, **meta):
        self.history.append({"event": event, "actor": actor, "at": datetime.now(timezone.utc).isoformat(), **meta})

def request_action(id, org_id, incident_id, action_type, params, requester_id, requester_role, origin="human") -> ResponseAction:
    if requester_role not in REQUESTER_ROLES:
        raise ResponseError("role not permitted to request actions")
    clean = validate_params(action_type, params)
    a = ResponseAction(id, org_id, incident_id, action_type, clean, requester_id, origin=origin)
    a._log("requested", requester_id, origin=origin)
    return a

def decide(action: ResponseAction, approver_id: str, approver_role: str, org_id: str, approve: bool) -> ResponseAction:
    if action.organization_id != org_id:
        raise ResponseError("action not found")  # org isolation: do not reveal existence
    if approver_role not in APPROVER_ROLES:
        raise ResponseError("role not permitted to approve actions")
    if action.approval_status != PENDING:
        raise ResponseError(f"action already {action.approval_status}")
    action.approval_status = APPROVED if approve else REJECTED
    action.approved_by = approver_id
    action._log("approved" if approve else "rejected", approver_id)
    return action

def cancel(action: ResponseAction, actor_id: str, actor_role: str, org_id: str) -> ResponseAction:
    if action.organization_id != org_id:
        raise ResponseError("action not found")
    if action.approval_status != PENDING:
        raise ResponseError("only pending actions can be cancelled")
    if actor_id != action.requested_by and actor_role not in APPROVER_ROLES:
        raise ResponseError("not permitted to cancel")
    action.approval_status = CANCELLED
    action._log("cancelled", actor_id)
    return action

def execute(action: ResponseAction, org_id: str, firewall: MockFirewall, handlers: dict | None = None) -> ResponseAction:
    """Idempotent: executing an already-executed action returns the stored result without re-running."""
    if action.organization_id != org_id:
        raise ResponseError("action not found")
    if action.execution_status == "executed":
        return action
    if action.approval_status != APPROVED:
        raise ResponseError("action is not approved")
    if action.action_type not in ALLOWED_ACTIONS:
        raise ResponseError("action type not allowlisted")
    try:
        if action.action_type == "block_ip_simulated":
            action.result = firewall.block(action.params["ip"])
        else:
            h = (handlers or {}).get(action.action_type)
            if h is None:
                raise ResponseError(f"no handler registered for {action.action_type}")
            action.result = h(action.params)
        action.execution_status = "executed"
        action._log("executed", action.approved_by or "system")
    except Exception as e:  # failure is recorded, never swallowed
        action.execution_status = FAILED
        action.result = {"error": str(e)}
        action._log("failed", "system", error=str(e))
    return action
