"""Correlate findings/alerts into incidents by shared entities within a window.
Time proximity alone never links alerts: they must share an entity (IP, user, or host)."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta

@dataclass
class AlertRef:
    id: str
    category: str
    severity: str
    timestamp: datetime
    entities: dict  # source_ip / username / hostname

@dataclass
class IncidentGroup:
    alert_ids: list[str] = field(default_factory=list)
    shared: set = field(default_factory=set)
    categories: set = field(default_factory=set)

def _keys(a: AlertRef) -> set:
    return {(k, v) for k, v in a.entities.items() if v and k in ("source_ip", "username", "hostname")}

def correlate(alerts: list[AlertRef], window_minutes: int = 60) -> list[IncidentGroup]:
    """Union-find over alerts sharing >=1 entity key within the window. Singletons are returned only
    if `min_size` logic is applied by caller; here every alert belongs to exactly one group."""
    alerts = sorted(alerts, key=lambda a: a.timestamp)
    parent = list(range(len(alerts)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    for i, a in enumerate(alerts):
        for j in range(i):
            b = alerts[j]
            if a.timestamp - b.timestamp <= timedelta(minutes=window_minutes) and _keys(a) & _keys(b):
                parent[find(i)] = find(j)
    groups: dict[int, IncidentGroup] = {}
    for i, a in enumerate(alerts):
        g = groups.setdefault(find(i), IncidentGroup())
        g.alert_ids.append(a.id)
        g.categories.add(a.category)
    for root, g in groups.items():
        members = [a for i, a in enumerate(alerts) if find(i) == root]
        common = None
        for a in members:
            common = _keys(a) if common is None else common & _keys(a)
        g.shared = common or set()
    return list(groups.values())
