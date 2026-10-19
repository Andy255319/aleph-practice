"""
Subject 4 이상탐지 전체 단위 및 통합 테스트 스위트
"""
import unittest
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_detection.normalize import run_normalization, normalize_timestamp
from anomaly_detection.login_detection import detect_bruteforce, detect_offhour_login
from anomaly_detection.traffic_detection import calculate_traffic_baseline, detect_traffic_spike
from anomaly_detection.advanced_detection import detect_unauthorized_access, detect_saas_anomaly, match_ioc
from anomaly_detection.correlation import group_by_user, check_chain, calculate_risk_score
from anomaly_detection.evaluation import evaluate_detector, generate_labeled_dataset
from agent_core.tool_router import global_router

class TestAnomalyDetectionPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        res = run_normalization()
        cls.events = res["events"]

    def test_day1_normalization(self):
        self.assertTrue(len(self.events) > 0)
        first = self.events[0]
        self.assertIn("event_id", first)
        self.assertIn("timestamp", first)
        self.assertIn("event_source", first)

    def test_day2_login_and_traffic(self):
        bf = detect_bruteforce(self.events)
        self.assertTrue(any(d["target_user"] == "user_david" for d in bf))

        off = detect_offhour_login(self.events)
        self.assertTrue(any(d["target_user"] == "user_night" for d in off))

        base = calculate_traffic_baseline(self.events)
        self.assertGreater(base["mean"], 0)
        spikes = detect_traffic_spike(self.events, baseline=base)
        self.assertTrue(any("192.168.1.100" in d["source_ip"] for d in spikes))

    def test_day3_advanced_and_correlation(self):
        ioc = match_ioc(self.events)
        self.assertTrue(any("198.51.100.23" in d["matched_ip"] for d in ioc))

        saas = detect_saas_anomaly(self.events)
        self.assertTrue(any(d["rule_id"] == "RULE-SAAS-MASS-DOWNLOAD" for d in saas))

        # 상관분석 3단계 킬체인 테스트
        mock_user_dets = [
            {"rule_id": "RULE-LOGIN-BRUTEFORCE", "rule_name": "무차별대입"},
            {"rule_id": "RULE-UNAUTHORIZED-ACCESS", "rule_name": "비인가접근"},
            {"rule_id": "RULE-SAAS-MASS-DOWNLOAD", "rule_name": "대량유출"}
        ]
        chain = check_chain([], mock_user_dets)
        self.assertTrue(chain["is_chain_completed"])

        score = calculate_risk_score("test_user", mock_user_dets, chain)
        self.assertGreaterEqual(score["risk_score"], 80)
        self.assertEqual(score["priority"], "HIGH")

    def test_day4_tuning_precision_recall(self):
        dataset = generate_labeled_dataset()
        before = evaluate_detector(dataset, apply_tuning=False)
        after = evaluate_detector(dataset, apply_tuning=True)

        self.assertGreater(before["fp"], 0)
        self.assertEqual(after["fp"], 0)
        self.assertEqual(after["precision"], 1.0)
        self.assertEqual(after["recall"], 1.0)

    def test_day5_agent_tool_router(self):
        tools = global_router.list_tools()
        self.assertIn("detect_bruteforce", tools)
        self.assertIn("match_ioc", tools)
        self.assertIn("calculate_risk_score", tools)

if __name__ == "__main__":
    unittest.main()
