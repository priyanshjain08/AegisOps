"""Strict validation of LLM investigation output + rule-based fallback.
AI output is data only: recommended actions are never executed, they become *pending* proposals."""
from __future__ import annotations
import json, re
from .response import ALLOWED_ACTIONS

REQUIRED_KEYS = ["executive_summary", "what_happened", "why_suspicious", "evidence", "attack_technique",
                 "potential_impact", "confidence", "investigation_steps", "recommended_actions", "missing_information"]
# Only techniques we allow the model to cite (extend deliberately; prevents fabricated IDs)
KNOWN_ATTACK_IDS = {"T1110": "Brute Force", "T1078": "Valid Accounts", "T1046": "Network Service Discovery",
                    "T1068": "Exploitation for Privilege Escalation", "T1098": "Account Manipulation",
                    "T1059": "Command and Scripting Interpreter", "T1562": "Impair Defenses",
                    "T1048": "Exfiltration Over Alternative Protocol", "T1041": "Exfiltration Over C2 Channel"}

class AIValidationError(ValueError):
    pass

def extract_json(text: str) -> dict:
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise AIValidationError(f"not valid JSON: {e}") from e
    if not isinstance(obj, dict):
        raise AIValidationError("top-level JSON must be an object")
    return obj

def validate_analysis(obj: dict, known_event_ids: set[str], known_alert_ids: set[str]) -> dict:
    missing = [k for k in REQUIRED_KEYS if k not in obj]
    if missing:
        raise AIValidationError(f"missing keys: {missing}")
    ev = obj["evidence"]
    if not isinstance(ev, list):
        raise AIValidationError("evidence must be a list")
    for item in ev:
        if not isinstance(item, dict) or item.get("kind") not in ("event", "alert") or not item.get("id"):
            raise AIValidationError("each evidence item needs kind (event|alert) and id")
        pool = known_event_ids if item["kind"] == "event" else known_alert_ids
        if str(item["id"]) not in pool:
            raise AIValidationError(f"evidence references unknown {item['kind']} id {item['id']!r} (possible fabrication)")
    conf = obj["confidence"]
    if not isinstance(conf, dict) or conf.get("level") not in ("low", "medium", "high") or not conf.get("uncertainty"):
        raise AIValidationError("confidence needs level (low|medium|high) and non-empty uncertainty")
    tech = obj["attack_technique"]
    if tech:
        techs = tech if isinstance(tech, list) else [tech]
        for t in techs:
            tid = t.get("id") if isinstance(t, dict) else None
            if tid and tid.split(".")[0] not in KNOWN_ATTACK_IDS:
                raise AIValidationError(f"unrecognized ATT&CK id {tid!r}")
    actions = obj["recommended_actions"]
    if not isinstance(actions, list):
        raise AIValidationError("recommended_actions must be a list")
    safe = []
    for a in actions:
        if not isinstance(a, dict) or a.get("action_type") not in ALLOWED_ACTIONS:
            raise AIValidationError(f"recommended action not allowlisted: {a!r}")
        safe.append({"action_type": a["action_type"], "params": a.get("params", {}), "rationale": str(a.get("rationale", ""))})
    out = dict(obj)
    out["recommended_actions"] = safe
    out["requires_human_approval"] = True
    return out

def fallback_analysis(incident: dict, alerts: list[dict], event_ids: list[str]) -> dict:
    """Deterministic, non-LLM summary built only from stored records."""
    cats = sorted({a["category"] for a in alerts})
    mapping = {"credential_access": "T1110", "initial_access": "T1078", "discovery": "T1046",
               "privilege_escalation": "T1098", "execution": "T1059", "defense_evasion": "T1562",
               "exfiltration": "T1048"}
    techs = [{"id": mapping[c], "name": KNOWN_ATTACK_IDS[mapping[c]], "basis": f"alert category '{c}' (heuristic mapping)"}
             for c in cats if c in mapping]
    return {
        "provider": "rule-based", "is_llm": False,
        "notice": "Non-LLM analysis. Configure AI_PROVIDER and AI_API_KEY on the backend to enable LLM analysis.",
        "executive_summary": f"{len(alerts)} related alert(s) grouped into incident '{incident['title']}' (severity {incident['severity']}). Heuristic detections only; nothing is confirmed.",
        "what_happened": [f"Alert {a['id']}: {a['title']}" for a in alerts],
        "why_suspicious": [a["description"] for a in alerts],
        "evidence": [{"kind": "alert", "id": a["id"]} for a in alerts] + [{"kind": "event", "id": e} for e in event_ids[:25]],
        "attack_technique": techs,
        "potential_impact": "Unknown without further investigation; depends on asset criticality and whether access succeeded.",
        "confidence": {"level": "low", "uncertainty": "Rule-based summary without contextual reasoning; hypotheses are not confirmed."},
        "investigation_steps": ["Review each related event in the timeline", "Verify source IP reputation with trusted intel", "Confirm with the account owner whether the activity was expected"],
        "recommended_actions": [],
        "missing_information": ["Authentication success context", "Threat intelligence on source IPs", "Endpoint telemetry"],
        "requires_human_approval": True,
    }
