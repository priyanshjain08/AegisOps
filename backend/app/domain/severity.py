"""Severity scoring (documented in SECURITY.md / ARCHITECTURE.md).

score = base(rule severity) + asset_criticality_bonus + confidence_adjustment, clamped to 0..100
base: informational=10 low=30 medium=50 high=70 critical=90
asset criticality bonus: low=0 medium=+3 high=+7 critical=+10
confidence adjustment: (confidence - 0.5) * 10   (confidence in 0..1)
bands: >=85 critical, >=65 high, >=40 medium, >=20 low, else informational
"""
BASE = {"informational": 10, "low": 30, "medium": 50, "high": 70, "critical": 90}
CRIT_BONUS = {"low": 0, "medium": 3, "high": 7, "critical": 10}

def score_alert(rule_severity: str, asset_criticality: str | None = None, confidence: float = 0.5) -> int:
    s = BASE[rule_severity] + CRIT_BONUS.get(asset_criticality or "low", 0) + (confidence - 0.5) * 10
    return int(max(0, min(100, round(s))))

def band(score: int) -> str:
    for threshold, name in ((85, "critical"), (65, "high"), (40, "medium"), (20, "low")):
        if score >= threshold:
            return name
    return "informational"
