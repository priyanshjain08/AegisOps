"""Simulated demo scenarios. Every record is tagged simulated=True."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone

def _ts(base, s): return (base + timedelta(seconds=s)).isoformat()

def scenario_brute_force(base: datetime) -> list[dict]:
    ip, out = "203.0.113.50", []
    for i in range(12):
        out.append({"timestamp": _ts(base, i * 20), "category": "authentication", "action": "login", "result": "failure",
                    "username": "admin", "source_ip": ip, "hostname": "web01", "simulated": True})
    out.append({"timestamp": _ts(base, 300), "category": "authentication", "action": "login", "result": "success",
                "username": "admin", "source_ip": ip, "hostname": "web01", "simulated": True})
    return out

def scenario_port_scan(base: datetime) -> list[dict]:
    return [{"timestamp": _ts(base, i), "category": "network", "action": "connect", "result": "denied",
             "source_ip": "198.51.100.77", "destination_ip": "10.0.1.20", "hostname": "fw01", "dest_port": 20 + i * 7,
             "simulated": True} for i in range(30)]

def scenario_priv_esc(base: datetime) -> list[dict]:
    return [
        {"timestamp": _ts(base, 0), "category": "authentication", "action": "login", "result": "success", "username": "svc_backup",
         "source_ip": "192.0.2.14", "hostname": "db01", "simulated": True},
        {"timestamp": _ts(base, 90), "category": "privilege", "action": "group_add", "group": "Administrators",
         "target_user": "svc_backup", "username": "svc_backup", "hostname": "db01", "simulated": True},
        {"timestamp": _ts(base, 150), "action": "av_disabled", "category": "security_control", "username": "svc_backup",
         "hostname": "db01", "simulated": True}]

def scenario_exfil(base: datetime) -> list[dict]:
    return [{"timestamp": _ts(base, i * 120), "category": "network", "action": "flow", "source_ip": "10.0.2.31",
             "destination_ip": "192.0.2.200", "hostname": "file01", "bytes_out": 180_000_000, "simulated": True}
            for i in range(4)]

SCENARIOS = {"brute_force": scenario_brute_force, "port_scan": scenario_port_scan,
             "privilege_escalation": scenario_priv_esc, "exfiltration": scenario_exfil}

def generate(names: list[str] | None = None, base: datetime | None = None) -> list[dict]:
    base = base or datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=2)
    recs = []
    for i, n in enumerate(names or SCENARIOS):
        recs.extend(SCENARIOS[n](base + timedelta(minutes=15 * i)))
    return recs
