import json, unittest
from datetime import datetime, timedelta, timezone
from app.domain.events import normalize_event, normalize_batch, parse_timestamp, EventValidationError
from app.domain.detection import default_rules, run_rules
from app.domain.correlation import AlertRef, correlate
from app.domain.severity import score_alert, band
from app.domain import response as R
from app.domain.ai_validation import validate_analysis, fallback_analysis, extract_json, AIValidationError

T0 = datetime(2026, 11, 1, 3, 0, tzinfo=timezone.utc)
def ev(i, **kw):
    d = {"timestamp": (T0 + timedelta(seconds=30 * i)).isoformat(), "category": "authentication",
         "action": "login", "result": "failure", "username": "admin", "source_ip": "203.0.113.5", "hostname": "web01"}
    d.update(kw); return normalize_event(d, "linux")
def rule(id_): return [r for r in default_rules() if r.id == id_]

class Normalization(unittest.TestCase):
    def test_timezones(self):
        self.assertEqual(parse_timestamp("2026-11-01T05:30:00+05:30"), datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc))
        self.assertEqual(parse_timestamp("2026-11-01T00:00:00").tzinfo, timezone.utc)
        self.assertEqual(parse_timestamp(0).year, 1970)
    def test_raw_preserved_and_attrs(self):
        e = normalize_event({"time": "2026-11-01T00:00:00Z", "event": "Login", "ip": "1.2.3.4", "extra": 7})
        self.assertEqual(e.raw["extra"], 7); self.assertEqual(e.attributes, {"extra": 7}); self.assertEqual(e.action, "login")
    def test_invalid_reported_not_dropped(self):
        events, errors = normalize_batch([{"timestamp": "x", "action": "a"}, {"timestamp": "2026-01-01T00:00:00Z"},
            {"timestamp": "2026-01-01T00:00:00Z", "action": "a", "source_ip": "999.1.1.1"}, "str",
            {"timestamp": "2026-01-01T00:00:00Z", "action": "ok"}])
        self.assertEqual(len(events), 1); self.assertEqual([e["index"] for e in errors], [0, 1, 2, 3])
    def test_duplicates(self):
        r = {"timestamp": "2026-01-01T00:00:00Z", "action": "a"}
        events, errors = normalize_batch([r, dict(r)])
        self.assertEqual(len(events), 1); self.assertIn("duplicate", errors[0]["error"])

class Detection(unittest.TestCase):
    def test_brute_force_fires_and_below_threshold_not(self):
        f = run_rules(rule("AG-001"), [ev(i) for i in range(6)]); self.assertEqual(len(f), 1)
        self.assertEqual(run_rules(rule("AG-001"), [ev(i) for i in range(4)]), [])
    def test_brute_force_window(self):
        evs = [ev(i * 200) for i in range(6)]  # 200s apart => >10min across 5 gaps
        self.assertEqual(run_rules(rule("AG-001"), evs), [])
    def test_brute_force_success_raises_severity(self):
        evs = [ev(i) for i in range(6)] + [ev(7, result="success")]
        f = run_rules(rule("AG-001"), evs)[0]; self.assertEqual(f.severity, "high"); self.assertIn("unconfirmed", f.description)
    def test_disabled_rule_skipped(self):
        r = rule("AG-001"); r[0].enabled = False; self.assertEqual(run_rules(r, [ev(i) for i in range(9)]), [])
    def test_threshold_configurable(self):
        r = rule("AG-001"); r[0].thresholds["failed_attempts"] = 2; self.assertEqual(len(run_rules(r, [ev(0), ev(1)])), 1)
    def test_suspicious_login(self):
        r = rule("AG-002"); r[0].thresholds["known_ips"] = ["10.0.0.1"]
        f = run_rules(r, [ev(0, result="success")]); self.assertEqual(len(f), 1)
    def test_priv_esc(self):
        e = normalize_event({"timestamp": T0.isoformat(), "category": "privilege", "action": "group_add", "group": "Administrators", "target_user": "bob"})
        self.assertEqual(len(run_rules(rule("AG-003"), [e])), 1)
    def test_port_scan(self):
        evs = [normalize_event({"timestamp": (T0 + timedelta(seconds=i)).isoformat(), "category": "network", "action": "connect",
               "source_ip": "198.51.100.9", "destination_ip": "10.0.0.5", "dest_port": 1000 + i}) for i in range(20)]
        f = run_rules(rule("AG-004"), evs); self.assertEqual(len(f), 1)
    def test_malware_needs_configured_indicators(self):
        e = normalize_event({"timestamp": T0.isoformat(), "category": "process", "action": "exec", "process_name": "mimikatz.exe"})
        self.assertEqual(run_rules(rule("AG-005"), [e]), [])
        r = rule("AG-005"); r[0].thresholds["process_names"] = ["mimikatz.exe"]; self.assertEqual(len(run_rules(r, [e])), 1)
    def test_suspicious_process(self):
        e = normalize_event({"timestamp": T0.isoformat(), "category": "process", "action": "exec", "command_line": "powershell -nop -enc AAAA"})
        self.assertEqual(len(run_rules(rule("AG-006"), [e])), 1)
    def test_exfil(self):
        e = normalize_event({"timestamp": T0.isoformat(), "category": "network", "action": "flow", "source_ip": "8.8.8.8", "bytes_out": 900_000_000})
        self.assertEqual(len(run_rules(rule("AG-007"), [e])), 1)
    def test_disabled_controls(self):
        e = normalize_event({"timestamp": T0.isoformat(), "action": "av_disabled", "hostname": "pc1"})
        self.assertEqual(len(run_rules(rule("AG-008"), [e])), 1)

class Correlation(unittest.TestCase):
    def a(self, id, ip=None, user=None, mins=0, host=None):
        return AlertRef(id, "x", "high", T0 + timedelta(minutes=mins), {"source_ip": ip, "username": user, "hostname": host})
    def test_shared_entity_groups(self):
        g = correlate([self.a("1", ip="1.1.1.1", mins=0), self.a("2", ip="1.1.1.1", user="u", mins=5), self.a("3", user="u", mins=9)])
        self.assertEqual(len(g), 1)
    def test_time_proximity_alone_does_not_group(self):
        g = correlate([self.a("1", ip="1.1.1.1"), self.a("2", ip="2.2.2.2", mins=1)]); self.assertEqual(len(g), 2)
    def test_window(self):
        g = correlate([self.a("1", ip="1.1.1.1"), self.a("2", ip="1.1.1.1", mins=500)], window_minutes=60); self.assertEqual(len(g), 2)

class Severity(unittest.TestCase):
    def test_scoring(self):
        self.assertEqual(band(score_alert("high", "critical", 0.9)), "high")
        self.assertEqual(score_alert("critical", "critical", 1.0), 100)
        self.assertEqual(band(score_alert("low")), "low")

class Response(unittest.TestCase):
    def mk(self, t="block_ip_simulated", p=None, role="analyst"):
        return R.request_action("a1", "org1", "inc1", t, p or {"ip": "203.0.113.5"}, "u1", role)
    def test_not_allowlisted(self):
        with self.assertRaises(R.ResponseError): self.mk("rm_rf", {})
    def test_shell_param_not_executable(self):
        with self.assertRaises(R.ResponseError): self.mk("block_ip_simulated", {"ip": "1.1.1.1; rm -rf /"})
    def test_private_ip_refused(self):
        with self.assertRaises(R.ResponseError): self.mk(p={"ip": "10.0.0.1"})
    def test_viewer_cannot_request(self):
        with self.assertRaises(R.ResponseError): self.mk(role="viewer")
    def test_analyst_cannot_approve(self):
        with self.assertRaises(R.ResponseError): R.decide(self.mk(), "u2", "analyst", "org1", True)
    def test_cross_org_blocked(self):
        with self.assertRaises(R.ResponseError): R.decide(self.mk(), "u2", "owner", "org2", True)
    def test_execute_requires_approval(self):
        with self.assertRaises(R.ResponseError): R.execute(self.mk(), "org1", R.MockFirewall())
    def test_full_flow_idempotent(self):
        a = self.mk(); fw = R.MockFirewall()
        R.decide(a, "u2", "security_admin", "org1", True); R.execute(a, "org1", fw); R.execute(a, "org1", fw)
        self.assertEqual(a.execution_status, "executed"); self.assertTrue(a.result["simulated"])
        self.assertEqual([h["event"] for h in a.history], ["requested", "approved", "executed"])
    def test_double_decision_rejected(self):
        a = self.mk(); R.decide(a, "u2", "owner", "org1", False)
        with self.assertRaises(R.ResponseError): R.decide(a, "u2", "owner", "org1", True)
    def test_failure_recorded(self):
        a = self.mk("add_note", {"note": "x"}); R.decide(a, "u2", "owner", "org1", True)
        R.execute(a, "org1", R.MockFirewall(), {"add_note": lambda p: 1 / 0}); self.assertEqual(a.execution_status, "failed")

class AI(unittest.TestCase):
    base = {"executive_summary": "s", "what_happened": [], "why_suspicious": [], "evidence": [{"kind": "event", "id": "e1"}],
            "attack_technique": [{"id": "T1110"}], "potential_impact": "p", "confidence": {"level": "low", "uncertainty": "u"},
            "investigation_steps": [], "recommended_actions": [{"action_type": "block_ip_simulated", "params": {"ip": "1.1.1.1"}}],
            "missing_information": []}
    def v(self, **kw):
        o = json.loads(json.dumps(self.base)); o.update(kw); return validate_analysis(o, {"e1"}, {"al1"})
    def test_valid(self): self.assertTrue(self.v()["requires_human_approval"])
    def test_fabricated_evidence(self):
        with self.assertRaises(AIValidationError): self.v(evidence=[{"kind": "event", "id": "evil"}])
    def test_fabricated_attack_id(self):
        with self.assertRaises(AIValidationError): self.v(attack_technique=[{"id": "T9999"}])
    def test_arbitrary_command_rejected(self):
        with self.assertRaises(AIValidationError): self.v(recommended_actions=[{"action_type": "shell", "params": {"cmd": "rm -rf /"}}])
    def test_missing_uncertainty(self):
        with self.assertRaises(AIValidationError): self.v(confidence={"level": "high", "uncertainty": ""})
    def test_bad_json(self):
        with self.assertRaises(AIValidationError): extract_json("nope")
        self.assertEqual(extract_json('```json\n{"a":1}\n```'), {"a": 1})
    def test_fallback_valid_and_labeled(self):
        fb = fallback_analysis({"title": "T", "severity": "high"}, [{"id": "al1", "title": "t", "description": "d", "category": "credential_access"}], ["e1"])
        self.assertFalse(fb["is_llm"]); validate_analysis(fb, {"e1"}, {"al1"})

if __name__ == "__main__":
    unittest.main()
