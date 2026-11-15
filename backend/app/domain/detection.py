"""Rule-based detection engine. Rules are pure functions over lists of NormalizedEvent.
Detections are heuristic indicators, NOT confirmed attacks."""
from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable
from .events import NormalizedEvent

@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    events: list[NormalizedEvent]
    confidence: float
    entities: dict  # e.g. {"source_ip": "...", "username": "..."}

@dataclass
class Rule:
    id: str
    name: str
    description: str
    category: str
    severity: str
    thresholds: dict
    evaluate: Callable[["Rule", list[NormalizedEvent]], list[Finding]]
    enabled: bool = True
    version: int = 1

def _window_groups(events, key, window, min_count):
    """Yield (key, [events]) where >= min_count events fall inside `window` (sliding)."""
    groups = defaultdict(list)
    for e in sorted(events, key=lambda x: x.timestamp):
        k = key(e)
        if k:
            groups[k].append(e)
    for k, evs in groups.items():
        start = 0
        best = []
        for end in range(len(evs)):
            while evs[end].timestamp - evs[start].timestamp > window:
                start += 1
            if end - start + 1 >= min_count and end - start + 1 > len(best):
                best = evs[start:end + 1]
        if best:
            yield k, best

def _is_failed_login(e):
    return e.category == "authentication" and e.action in ("login", "logon", "login_failed") and (
        e.result in ("failure", "failed", "fail") or e.action == "login_failed")

def brute_force(rule, events):
    t = rule.thresholds
    out = []
    for key, evs in _window_groups([e for e in events if _is_failed_login(e)],
                                   lambda e: (e.source_ip, e.username) if e.source_ip or e.username else None,
                                   timedelta(minutes=t["window_minutes"]), t["failed_attempts"]):
        ip, user = key
        succ = [e for e in events if e.category == "authentication" and e.result in ("success", "succeeded")
                and e.username == user and e.source_ip == ip and e.timestamp >= evs[-1].timestamp]
        conf = 0.6 + (0.2 if len(evs) >= 2 * t["failed_attempts"] else 0) + (0.15 if succ else 0)
        out.append(Finding(rule.id, f"Possible brute force against {user or 'unknown account'}",
            f"{len(evs)} failed logins within {t['window_minutes']} min from {ip or 'unknown IP'}."
            + (" A successful login from the same source followed (possible compromise; unconfirmed)." if succ else ""),
            "high" if succ else rule.severity, rule.category, evs + succ[:1], min(conf, 0.95),
            {"source_ip": ip, "username": user}))
    return out

def suspicious_login(rule, events):
    t = rule.thresholds
    known = set(t.get("known_ips", []))
    out = []
    for e in events:
        if e.category == "authentication" and e.result in ("success", "succeeded") and e.username:
            reasons = []
            if known and e.source_ip and e.source_ip not in known:
                reasons.append(f"unfamiliar source IP {e.source_ip}")
            h = e.timestamp.hour
            if t["off_hours_start"] > t["off_hours_end"]:
                off = h >= t["off_hours_start"] or h < t["off_hours_end"]
            else:
                off = t["off_hours_start"] <= h < t["off_hours_end"]
            if off:
                reasons.append(f"login at off-hours ({h:02d}:00 UTC)")
            if reasons:
                out.append(Finding(rule.id, f"Unusual login for {e.username}", "; ".join(reasons).capitalize() + ".",
                    rule.severity, rule.category, [e], 0.4 + 0.15 * len(reasons),
                    {"source_ip": e.source_ip, "username": e.username}))
    return out

def privilege_escalation(rule, events):
    groups = {g.lower() for g in rule.thresholds["admin_groups"]}
    out = []
    for e in events:
        grp = str(e.attributes.get("group", "")).lower()
        if e.category == "privilege" and e.action in ("group_add", "privilege_grant", "role_change") and (
                grp in groups or e.attributes.get("elevated") is True):
            out.append(Finding(rule.id, f"Privilege change for {e.attributes.get('target_user') or e.username}",
                f"Action {e.action} involving privileged group/role {grp or 'elevated'}.", rule.severity,
                rule.category, [e], 0.65, {"username": e.attributes.get("target_user") or e.username,
                                           "hostname": e.hostname}))
    return out

def port_scan(rule, events):
    t = rule.thresholds
    conns = [e for e in events if e.category == "network" and e.source_ip and e.attributes.get("dest_port") is not None]
    out = []
    for ip, evs in _window_groups(conns, lambda e: e.source_ip, timedelta(minutes=t["window_minutes"]), 1):
        ports = {e.attributes["dest_port"] for e in evs}
        hosts = {e.destination_ip or e.hostname for e in evs}
        if len(ports) >= t["distinct_ports"] or len(hosts) >= t["distinct_hosts"]:
            out.append(Finding(rule.id, f"Possible port scan from {ip}",
                f"{len(evs)} connection attempts touching {len(ports)} ports and {len(hosts)} hosts.",
                rule.severity, rule.category, evs, 0.7, {"source_ip": ip}))
    return out

def malware_indicators(rule, events):
    t = rule.thresholds
    names = {n.lower() for n in t["process_names"]}
    hashes = {h.lower() for h in t["hashes"]}
    out = []
    for e in events:
        p = str(e.attributes.get("process_name", "")).lower()
        h = str(e.attributes.get("file_hash", "")).lower()
        if (p and p in names) or (h and h in hashes):
            out.append(Finding(rule.id, "Configured malware indicator matched",
                f"Matched user-supplied indicator (process={p or '-'}, hash={h or '-'}). "
                "This is an indicator match, not malware analysis.", rule.severity, rule.category, [e],
                0.75, {"hostname": e.hostname, "username": e.username}))
    return out

def suspicious_process(rule, events):
    pats = [re.compile(p, re.I) for p in rule.thresholds["command_patterns"]]
    out = []
    for e in events:
        cmd = str(e.attributes.get("command_line", ""))
        if e.category == "process" and cmd and any(p.search(cmd) for p in pats):
            out.append(Finding(rule.id, "Suspicious command pattern executed",
                f"Command line matched a configured pattern: {cmd[:200]}", rule.severity, rule.category,
                [e], 0.6, {"hostname": e.hostname, "username": e.username}))
    return out

def exfiltration(rule, events):
    t = rule.thresholds
    out = []
    flows = [e for e in events if e.category == "network" and isinstance(e.attributes.get("bytes_out"), (int, float))]
    for ip, evs in _window_groups(flows, lambda e: e.source_ip or e.hostname, timedelta(minutes=t["window_minutes"]), 1):
        total = sum(e.attributes["bytes_out"] for e in evs)
        if total >= t["bytes_threshold"]:
            out.append(Finding(rule.id, f"High outbound volume from {ip}",
                f"{total/1e6:.1f} MB outbound within {t['window_minutes']} min (threshold {t['bytes_threshold']/1e6:.0f} MB). "
                "Volume alone does not confirm exfiltration.", rule.severity, rule.category, evs, 0.5,
                {"source_ip": evs[0].source_ip, "hostname": evs[0].hostname}))
    return out

def disabled_controls(rule, events):
    acts = set(rule.thresholds["actions"])
    return [Finding(rule.id, "Security control disabled",
            f"Event {e.action} on {e.hostname or 'unknown host'} indicates monitoring/protection was turned off.",
            rule.severity, rule.category, [e], 0.7, {"hostname": e.hostname, "username": e.username})
            for e in events if e.action in acts]

def default_rules() -> list[Rule]:
    return [
        Rule("AG-001", "Brute Force Login Attempts", "Repeated failed logins for one source/account in a window.",
             "credential_access", "medium", {"failed_attempts": 5, "window_minutes": 10}, brute_force),
        Rule("AG-002", "Suspicious Login", "Successful login from unfamiliar IP or at off-hours.",
             "initial_access", "medium", {"known_ips": [], "off_hours_start": 22, "off_hours_end": 6}, suspicious_login),
        Rule("AG-003", "Privilege Escalation", "Admin group additions / elevated access events.",
             "privilege_escalation", "high", {"admin_groups": ["administrators", "domain admins", "root", "sudo", "wheel"]}, privilege_escalation),
        Rule("AG-004", "Port Scanning Indicators", "One source touching many ports or hosts.",
             "discovery", "medium", {"distinct_ports": 15, "distinct_hosts": 10, "window_minutes": 5}, port_scan),
        Rule("AG-005", "Malware Indicators", "Matches user-supplied process names / hashes.",
             "execution", "high", {"process_names": [], "hashes": []}, malware_indicators),
        Rule("AG-006", "Suspicious Process Execution", "Command lines matching configurable patterns.",
             "execution", "medium", {"command_patterns": [r"powershell.*-enc", r"certutil.*-urlcache", r"nc(\.exe)?\s+-e", r"/dev/tcp/"]}, suspicious_process),
        Rule("AG-007", "Data Exfiltration Indicators", "Unusually large outbound transfer volume.",
             "exfiltration", "medium", {"bytes_threshold": 500_000_000, "window_minutes": 30}, exfiltration),
        Rule("AG-008", "Disabled Security Controls", "Monitoring/protection disabled events.",
             "defense_evasion", "high", {"actions": ["av_disabled", "firewall_disabled", "audit_disabled", "edr_stopped"]}, disabled_controls),
    ]

def run_rules(rules: list[Rule], events: list[NormalizedEvent]) -> list[Finding]:
    out = []
    for r in rules:
        if r.enabled:
            out.extend(r.evaluate(r, events))
    return out
