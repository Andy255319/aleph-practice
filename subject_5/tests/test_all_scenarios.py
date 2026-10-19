"""
통합 단위 테스트 및 시나리오 검증 스위트
"""
import unittest
import os
import sys
import json

# 모듈 경로 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.incident import Incident, update_status, match_playbook
from soar.containment import (
    lock_account,
    unlock_account,
    block_ip,
    unblock_ip,
    terminate_session,
    VIPAccountException,
    MissingReasonException,
    get_all_containment_logs
)
from soar.ticketing import create_ticket, sync_ticket_status, get_ticket
from soar.escalation import escalate
from soar.approval_gate import execute_action, handle_false_positive
from soar.report import generate_reports, collect_incident_data

class TestSOARFullPipeline(unittest.TestCase):

    def test_day1_incident_and_playbook(self):
        inc = Incident(
            incident_id="TEST-INC-001",
            event_type="abnormal_login",
            severity="HIGH",
            source_ip="1.2.3.4",
            target_account="user_test",
            description="테스트 비정상 로그인"
        )
        self.assertEqual(inc.status, "NEW")
        pb = match_playbook("abnormal_login")
        self.assertIsNotNone(pb)
        self.assertEqual(pb["id"], "PB-001")

        update_status(inc, "ANALYZING", "분석 시작")
        self.assertEqual(inc.status, "ANALYZING")
        self.assertEqual(len(inc.history), 2)

    def test_day2_containment_and_vip_protection(self):
        # 1. 일반 계정 잠금
        res = lock_account("test_user_normal", "테스트 사유")
        self.assertEqual(res["status"], "SUCCESS")

        # 2. VIP 계정 잠금 시도 시 VIPAccountException 발생
        with self.assertRaises(VIPAccountException):
            lock_account("ceo_kim", "VIP 자동 잠금 시도")

        # 3. VIP 계정 승인 후 잠금 성공
        res_vip = lock_account("ceo_kim", "VIP 승인 완료 잠금", is_approved=True)
        self.assertEqual(res_vip["status"], "SUCCESS")

        # 4. 차단 해제 시 사유 누락 검증
        with self.assertRaises(MissingReasonException):
            unlock_account("test_user_normal", "")

        # 5. 해제 정상 수행
        unres = unlock_account("test_user_normal", "정상 확인 후 해제")
        self.assertEqual(unres["status"], "SUCCESS")

    def test_day3_ticketing_and_escalation(self):
        inc_data = {
            "incident_id": "TEST-INC-002",
            "event_type": "traffic_spike",
            "severity": "CRITICAL",
            "source_ip": "10.0.0.99",
            "target_account": "api_gateway",
            "description": "트래픽 폭주"
        }
        actions = [
            {"timestamp": "2026-10-19T10:00:00", "action_type": "block_ip", "target": "10.0.0.99", "status": "SUCCESS", "details": "차단 완료"}
        ]
        ticket = create_ticket(inc_data, actions)
        self.assertTrue(ticket["ticket_id"].startswith("SEC-"))
        self.assertIn("10.0.0.99", ticket["body"])

        # 에스컬레이션 테스트
        esc = escalate(ticket["ticket_id"], current_tier=1, reason="1차 분석가 무응답", simulated_elapsed_minutes=25)
        self.assertTrue(esc["escalated"])
        self.assertEqual(esc["new_tier"], 2)
        self.assertIn("secops_lead", esc["new_assignee"])

    def test_day4_approval_gate_and_false_positive(self):
        # 1. Low 위험도 -> 자동 실행
        res_low = execute_action("terminate_session", "session_user", {"session_id": "s1", "reason": "테스트"})
        self.assertTrue(res_low["success"])
        self.assertEqual(res_low["status"], "EXECUTED")

        # 2. High 위험도 승인자 없음 -> APPROVAL_PENDING
        res_high_no_app = execute_action("block_ip", "1.1.1.1", {"reason": "스캔 차단"})
        self.assertFalse(res_high_no_app["success"])
        self.assertEqual(res_high_no_app["status"], "APPROVAL_PENDING")

        # 3. High 위험도 승인자 포함 -> EXECUTED
        res_high_app = execute_action("block_ip", "1.1.1.1", {"reason": "스캔 차단"}, approver="MANAGER_PARK")
        self.assertTrue(res_high_app["success"])
        self.assertEqual(res_high_app["status"], "EXECUTED")

        # 4. 오탐 복구 테스트
        fp_res = handle_false_positive(
            incident_id="FP-001",
            target_account="acc_fp",
            target_ip="9.9.9.9",
            fp_reason="정기 모의해킹"
        )
        self.assertEqual(fp_res["status"], "FALSE_POSITIVE_RESOLVED")
        self.assertEqual(fp_res["labeled_data_recorded"]["ground_truth_label"], "FALSE_POSITIVE")

    def test_day4_report_generation(self):
        inc_data = {
            "incident_id": "TEST-INC-REPORT",
            "event_type": "abnormal_login",
            "severity": "HIGH",
            "source_ip": "8.8.8.8",
            "target_account": "user_rep",
            "description": "리포트 테스트",
            "status": "CONTAINMENT",
            "history": []
        }
        reports = generate_reports(inc_data)
        self.assertTrue(os.path.exists(reports["technical_report"]))
        self.assertTrue(os.path.exists(reports["executive_report"]))

if __name__ == "__main__":
    unittest.main()
