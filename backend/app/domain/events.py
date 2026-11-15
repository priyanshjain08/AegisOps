"""Event normalization: raw records -> common event structure. Pure Python, no I/O."""
from __future__ import annotations
import hashlib, json, ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("informational", "low", "medium", "high", "critical")

class EventValidationError(ValueError):
    pass

@dataclass
class NormalizedEvent:
    timestamp: datetime
    source_type: str
    category: str
    action: str
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    severity: str = "informational"
    result: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    dedup_hash: str = ""

def parse_timestamp(value: Any) -> datetime:
    """Parse ISO-8601 or epoch seconds; naive values are treated as UTC. Always returns aware UTC."""
    if value is None or value == "":
        raise EventValidationError("timestamp is required")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        try:
            return datetime.fromtimestamp(float(s), tz=timezone.utc)
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError as e:
            raise EventValidationError(f"invalid timestamp {value!r}") from e
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    raise EventValidationError(f"invalid timestamp type {type(value).__name__}")

def _ip(value: Any, name: str) -> str | None:
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as e:
        raise EventValidationError(f"invalid {name} {value!r}") from e

_ALIASES = {
    "hostname": ("hostname", "host", "computer"),
    "username": ("username", "user", "account"),
    "source_ip": ("source_ip", "src_ip", "ip"),
    "destination_ip": ("destination_ip", "dst_ip", "dest_ip"),
    "category": ("category", "event_category"),
    "action": ("action", "event_action", "event"),
    "result": ("result", "status", "outcome"),
    "severity": ("severity", "level"),
    "timestamp": ("timestamp", "time", "@timestamp", "ts"),
}
_SEV_MAP = {"info": "informational", "warn": "medium", "warning": "medium", "error": "high",
            "fatal": "critical", "crit": "critical"}
_KNOWN = {a for v in _ALIASES.values() for a in v}

def _pick(rec: dict, key: str):
    for a in _ALIASES[key]:
        if a in rec and rec[a] not in (None, ""):
            return rec[a]
    return None

def normalize_event(record: dict[str, Any], source_type: str = "generic") -> NormalizedEvent:
    if not isinstance(record, dict):
        raise EventValidationError("record must be a JSON object")
    ts = parse_timestamp(_pick(record, "timestamp"))
    action = _pick(record, "action")
    if not action:
        raise EventValidationError("action is required")
    sev = str(_pick(record, "severity") or "informational").lower()
    sev = _SEV_MAP.get(sev, sev)
    if sev not in SEVERITIES:
        raise EventValidationError(f"invalid severity {sev!r}")
    ev = NormalizedEvent(
        timestamp=ts, source_type=source_type,
        category=str(_pick(record, "category") or "general").lower(),
        action=str(action).lower(),
        hostname=(str(_pick(record, "hostname")).lower() if _pick(record, "hostname") else None),
        username=(str(_pick(record, "username")) if _pick(record, "username") else None),
        source_ip=_ip(_pick(record, "source_ip"), "source_ip"),
        destination_ip=_ip(_pick(record, "destination_ip"), "destination_ip"),
        severity=sev,
        result=(str(_pick(record, "result")).lower() if _pick(record, "result") else None),
        raw=dict(record),
        attributes={k: v for k, v in record.items() if k not in _KNOWN},
    )
    ev.dedup_hash = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
    return ev

def normalize_batch(records: list[Any], source_type: str = "generic"):
    """Returns (events, errors). Invalid records are reported with index, never silently dropped.
    Exact duplicates within the batch are reported as errors too."""
    events, errors, seen = [], [], set()
    for i, rec in enumerate(records):
        try:
            ev = normalize_event(rec, source_type)
        except EventValidationError as e:
            errors.append({"index": i, "error": str(e)})
            continue
        if ev.dedup_hash in seen:
            errors.append({"index": i, "error": "duplicate record in batch"})
            continue
        seen.add(ev.dedup_hash)
        events.append(ev)
    return events, errors
