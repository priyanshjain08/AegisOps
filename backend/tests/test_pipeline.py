import unittest
from datetime import datetime, timezone
from app.domain.scenarios import generate, SCENARIOS
from app.domain.pipeline import process
from app.domain import response as R
from app.domain.ai_validation import fallback_analysis, validate_analysis

BASE = datetime(2026, 11, 1, 3, 0, tzinfo=timezone.utc)

class EndToEnd(unittest.TestCase):
    def test_each_scenario_triggers_expected_rule(self):
        expected = {"brute_force": "AG-001", "port_scan": "AG-004", "privilege_escalation": "AG-003", "exfiltration": "AG-007"}
        for name, rid in expected.items():
            res = process(generate([name], BASE))
            self.assertIn(rid, {a["finding"].rule_id for a in res["alerts"]}, name)
            self.assertEqual(res["errors"], [])

    def test_priv_esc_alerts_correlate_by_user_and_host(self):
        res = process(generate(["privilege_escalation"], BASE))
        # AG-002 (03:00 UTC is off-hours), AG-003, AG-008
        self.assertEqual({a["finding"].rule_id for a in res["alerts"]}, {"AG-002", "AG-003", "AG-008"})
        self.assertEqual(len(res["incidents"]), 1)

    def test_unrelated_scenarios_stay_separate_incidents(self):
        res = process(generate(None, BASE))
        self.assertGreaterEqual(len(res["incidents"]), 4)

    def test_full_workflow(self):
        res = process(generate(["brute_force"], BASE))
        alert = res["alerts"][0]; inc = res["incidents"][0]
        self.assertIn(alert["id"], inc.alert_ids)
        ev_ids = {i for a in res["alerts"] for i in a["event_ids"]}
        fb = fallback_analysis({"title": "inc", "severity": alert["severity"]},
                               [{"id": a["id"], "title": a["finding"].title, "description": a["finding"].description,
                                 "category": a["finding"].category} for a in res["alerts"]], sorted(ev_ids))
        validate_analysis(fb, ev_ids, {a["id"] for a in res["alerts"]})
        act = R.request_action("act1", "org", "inc", "block_ip_simulated", {"ip": "203.0.113.50"}, "analyst1", "analyst")
        self.assertEqual(act.approval_status, R.PENDING)
        R.decide(act, "admin1", "security_admin", "org", True)
        R.execute(act, "org", R.MockFirewall())
        self.assertEqual(act.execution_status, "executed")
        self.assertTrue(all(r.get("simulated") for r in generate(["brute_force"], BASE)))

if __name__ == "__main__":
    unittest.main()
