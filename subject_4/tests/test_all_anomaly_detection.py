"""
Subject 4 이상탐지 전체 단위 및 통합 테스트 스위트
(Day 1 ~ Day 5 슬라이드 및 실습 교재 명세 검증)
"""
import unittest
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_detection.explore_logs import explore_all_logs
from anomaly_detection.normalize import run_normalization, normalize_timestamp
from anomaly_detection.login_detection import detect_bruteforce, detect_offhour_login, is_offhour_single_event
from anomaly_detection.traffic_detection import calculate_traffic_baseline, detect_traffic_spike
from anomaly_detection.advanced_detection import detect_unauthorized_access, detect_saas_anomaly, match_ioc
from anomaly_detection.correlation import group_by_user, check_chain, calculate_risk_score, correlate_events
from anomaly_detection.evaluation import evaluate_detector, generate_labeled_dataset
from agent_core.tool_router import global_router

class TestAnomalyDetectionPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        res = run_normalization()
        cls.events = res["events"]

    def test_day1_data_exploration_and_normalization(self):
        """Day 1: CSV 결측치 및 이상 타임스탬프 탐색 및 공통 스키마 정규화 검증"""
        exp = explore_all_logs()
        self.assertIn("login_logs", exp)
        self.assertIn("firewall_logs", exp)
        self.assertIn("saas_logs", exp)

        # 정규화된 이벤트 유효성 검증
        self.assertTrue(len(self.events) > 0)
        first = self.events[0]
        self.assertIn("event_id", first)
        self.assertIn("timestamp", first)
        self.assertIn("event_source", first)
        self.assertIn("user_id", first)
        self.assertIn("source_ip", first)

        # not-a-time 이 정제되어 필터링되었는지 검증
        for ev in self.events:
            self.assertNotEqual(ev["timestamp"], "not-a-time")

    def test_day2_login_and_traffic_detection(self):
        """Day 2: detect_bruteforce, detect_offhour_login, detect_traffic_spike 검증"""
        # 1. detect_bruteforce(): lee 사용자의 5초 내 연속 실패 후 성공 탐지
        bf = detect_bruteforce(self.events, threshold=2)
        self.assertTrue(any(d["target_user"] == "lee" for d in bf))

        # 2. detect_offhour_login(): choi 사용자의 23:48:02 심야 로그인 단일 이벤트 평가
        off = detect_offhour_login(self.events)
        self.assertTrue(any(d["target_user"] == "choi" for d in off))

        # 3. detect_traffic_spike(): 여러 시점의 데이터 비교 기반 트래픽 급증 탐지
        base = calculate_traffic_baseline(self.events)
        self.assertGreater(base["mean_connections"], 0)
        spikes = detect_traffic_spike(self.events, baseline=base)
        self.assertTrue(len(spikes) > 0)

    def test_day3_advanced_detection_and_correlation(self):
        """Day 3: detect_unauthorized_access, detect_saas_anomaly, match_ioc, correlate_events 검증"""
        # 1. detect_unauthorized_access(): 방화벽 DENY 및 RBAC 위반 변환
        unauth = detect_unauthorized_access(self.events)
        self.assertTrue(len(unauth) > 0)
        self.assertTrue(any(d["target_port"] == 22 for d in unauth))

        # 2. detect_saas_anomaly(): lee의 심야 drive DOWNLOAD 및 kim의 급속 연속 다운로드
        saas = detect_saas_anomaly(self.events)
        self.assertTrue(len(saas) > 0)
        self.assertTrue(any(d["user_id"] == "lee" for d in saas))

        # 3. match_ioc(): IoC 피드 악성 IP 매칭
        ioc = match_ioc(self.events)
        self.assertTrue(len(ioc) > 0)
        self.assertTrue(any(d["rule_id"] == "RULE-IOC-MATCH" for d in ioc))

        # 4. correlate_events(): 사용자별 다단계 킬체인 및 이벤트 관계 평가
        all_dets = bf = detect_bruteforce(self.events, threshold=2) + detect_offhour_login(self.events) + unauth + saas + ioc
        corr = correlate_events(self.events, all_dets)
        self.assertIn("lee", corr)
        lee_info = corr["lee"]
        self.assertTrue(lee_info["chain_analysis"]["is_chain_completed"])
        self.assertEqual(lee_info["risk_evaluation"]["priority"], "HIGH")

    def test_day4_tuning_precision_recall(self):
        """Day 4: 기존 탐지룰 튜닝(오탐 감소) 120분 명세 검증"""
        dataset = generate_labeled_dataset()
        before = evaluate_detector(dataset, apply_tuning=False)
        after = evaluate_detector(dataset, apply_tuning=True)

        # 튜닝 전 오탐(FP) 발생 확인
        self.assertGreater(before["fp"], 0)
        self.assertLess(before["precision"], 1.0)

        # 튜닝 후 오탐 0건 및 Precision 100%, Recall 100% 달성 확인
        self.assertEqual(after["fp"], 0)
        self.assertEqual(after["precision"], 1.0)
        self.assertEqual(after["recall"], 1.0)
        self.assertEqual(after["f1_score"], 1.0)

    def test_day5_agent_tool_router_registry(self):
        """Day 5: 슬라이드 표 6대 탐지 함수 및 상관분석 도구 등록 검증"""
        tools = global_router.list_tools()
        expected_tools = [
            "detect_bruteforce",
            "detect_offhour_login",
            "detect_traffic_spike",
            "detect_unauthorized_access",
            "detect_saas_anomaly",
            "match_ioc",
            "correlate_events",
            "calculate_risk_score"
        ]
        for tool_name in expected_tools:
            self.assertIn(tool_name, tools)

if __name__ == "__main__":
    unittest.main()
