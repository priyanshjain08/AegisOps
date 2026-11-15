"""Provider-independent LLM layer. Keys live only in backend env; output is validated before storage."""
import json
import httpx
from app.core.config import settings
from app.domain.ai_validation import extract_json, validate_analysis, fallback_analysis, AIValidationError

SYSTEM = ("You are a SOC investigation assistant. Use ONLY the provided incident data. Never invent events, IDs, or IOCs. "
          "Distinguish observed facts from hypotheses. Never state an attack is confirmed without evidence. "
          "Only cite MITRE ATT&CK IDs genuinely supported. Respond with ONE JSON object with keys: executive_summary, "
          "what_happened, why_suspicious, evidence (list of {kind:'event'|'alert', id}), attack_technique (list of {id,name,basis}), "
          "potential_impact, confidence ({level:'low'|'medium'|'high', uncertainty}), investigation_steps, "
          "recommended_actions (list of {action_type, params, rationale}; allowed action_type: acknowledge_alert, assign_incident, "
          "add_note, disable_detection_rule, generate_report, create_recommendation, block_ip_simulated), missing_information.")

def _call(context: dict) -> str:
    prompt = json.dumps(context, default=str)
    if settings.ai_provider == "anthropic":
        r = httpx.post((settings.ai_base_url or "https://api.anthropic.com") + "/v1/messages", timeout=60,
            headers={"x-api-key": settings.ai_api_key, "anthropic-version": "2023-06-01"},
            json={"model": settings.ai_model, "max_tokens": 2000, "system": SYSTEM, "messages": [{"role": "user", "content": prompt}]})
        r.raise_for_status(); return r.json()["content"][0]["text"]
    if settings.ai_provider == "openai":
        r = httpx.post((settings.ai_base_url or "https://api.openai.com/v1") + "/chat/completions", timeout=60,
            headers={"Authorization": f"Bearer {settings.ai_api_key}"},
            json={"model": settings.ai_model, "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
                  "response_format": {"type": "json_object"}})
        r.raise_for_status(); return r.json()["choices"][0]["message"]["content"]
    raise RuntimeError("no provider")

def analyze(incident: dict, alerts: list[dict], events: list[dict], notes: list[str]) -> dict:
    """Returns {content, provider, model, is_llm}. Falls back (clearly labeled) on missing key or invalid output."""
    event_ids = {e["id"] for e in events}; alert_ids = {a["id"] for a in alerts}
    if settings.ai_provider in ("openai", "anthropic") and settings.ai_api_key and settings.ai_model:
        try:
            parsed = extract_json(_call({"incident": incident, "alerts": alerts, "events": events[:200], "notes": notes}))
            content = validate_analysis(parsed, event_ids, alert_ids)
            content.update(provider=settings.ai_provider, is_llm=True)
            return {"content": content, "provider": settings.ai_provider, "model": settings.ai_model, "is_llm": True}
        except (AIValidationError, httpx.HTTPError, RuntimeError, KeyError) as e:
            fb = fallback_analysis(incident, alerts, sorted(event_ids))
            fb["notice"] = f"LLM analysis unavailable or rejected by validation ({type(e).__name__}: {str(e)[:200]}). Showing non-LLM analysis."
            return {"content": fb, "provider": "rule-based", "model": None, "is_llm": False}
    return {"content": fallback_analysis(incident, alerts, sorted(event_ids)), "provider": "rule-based", "model": None, "is_llm": False}
