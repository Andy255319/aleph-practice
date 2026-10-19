"""
통합 단위 테스트 및 시나리오 검증 스위트 (슬라이드 명세 반영)
"""
import unittest
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.incident import Incident, update_status, match_playbook
from soar.containment import (
    lock_account,
    unlock_account,
    block_ip,
    unblock_ip,
    terminate_session,
    VIPApprovalRequired,
    is_vip_account,
    get_all_containment_logs
)
from soar.ticketing import create_ticket, sync_ticket_status, get_ticket
from soar.escalation import check_and_escalate
from soar.approval_gate import execute_action, handle_false_positive

class TestSOARSlideScenarios(unittest.TestCase):

    def test_day1_slide_incident_and_playbook_matching(self):
        """DAY 1 슬라이드 명세: incident 딕셔너리 구조, update_status, 3대 플레이북 매칭"""
        # 1. incident 구조
        incident = {
            "event_id": "evt-2001",
            "status": "triaged",
            "history": [
                {"status": "detected", "message": "비정상 로그인 탐지"},
                {"status": "triaged", "message": "위험도 분석 및 분류 완료"}
            ]
        }
        self.assertEqual(incident["event_id"], "evt-2001")
        self.assertEqual(incident["status"], "triaged")

        # 2. update_status 동작
        update_status(incident, "containment", "계정 및 IP 격리 시작")
        self.assertEqual(incident["status"], "containment")
        self.assertEqual(len(incident["history"]), 3)
        self.assertEqual(incident["history"][-1]["message"], "계정 및 IP 격리 시작")

        # 3. 3대 플레이북 매칭 (PB-LOGIN-001, PB-TRAFFIC-001, PB-CORRELATION-001)
        pb1 = match_playbook("ABNORMAL_LOGIN")
        self.assertEqual(pb1["id"], "PB-LOGIN-001")
        self.assertEqual(pb1["response_level"], "승인 후 조치")

        pb2 = match_playbook("TRAFFIC_SPIKE")
        self.assertEqual(pb2["id"], "PB-TRAFFIC-001")
        self.assertEqual(pb2["response_level"], "즉시 자동조치")

        pb3 = match_playbook("CORRELATED_ATTACK")
        self.assertEqual(pb3["id"], "PB-CORRELATION-001")
        self.assertEqual(pb3["response_level"], "승인 후 조치")

    def test_day2_scenario_a_normal_account_lock(self):
        """시나리오 A: 일반 계정(lee) 자동 잠금"""
        res = lock_account("lee", "비정상 로그인 반복")

        self.assertEqual(res["result"], "SUCCESS")
        self.assertEqual(res["target"], "lee")

    def test_day2_scenario_b_vip_approval_required(self):
        """시나리오 B: VIP 계정(kim) 잠금 시 VIPApprovalRequired 예외 발생 및 기록"""
        self.assertTrue(is_vip_account("kim"))
        with self.assertRaises(VIPApprovalRequired):
            lock_account("kim", "계정 탈취 의심")

        # containment_log에 APPROVAL_REQUIRED 기록 확인
        logs = get_all_containment_logs()
        vip_logs = [l for l in logs if l.get("target") == "kim" and l.get("result") == "APPROVAL_REQUIRED"]
        self.assertTrue(len(vip_logs) > 0)

    def test_day2_scenario_c_ip_block_and_session_terminate(self):
        """시나리오 C: IP 차단(203.0.113.25)과 세션 종료(lee) 결합"""
        res_ip = block_ip("203.0.113.25", "악성 IP에서 비정상 로그인 탐지")
        res_sess = terminate_session("lee", "악성 IP에서 비정상 로그인 탐지")
        self.assertEqual(res_ip["result"], "SUCCESS")
        self.assertEqual(res_sess["result"], "SUCCESS")

    def test_day2_additional_unlock_and_unblock(self):
        """추가 테스트: 사유 누락 검사 및 정상 해제/중복 해제"""
        # 사유 누락
        fail_un = unlock_account("lee", "   ")
        self.assertEqual(fail_un["result"], "FAIL")

        # 정상 잠금 후 해제
        lock_account("user_test", "잠금 테스트")
        ok_un = unlock_account("user_test", "정상 확인 후 해제")
        self.assertEqual(ok_un["result"], "SUCCESS")

        # 이미 해제된 대상
        skip_un = unlock_account("user_test", "중복 해제")
        self.assertEqual(skip_un["result"], "SKIPPED")

    def test_day3_tc01_tc02_ticket_creation(self):
        """TC-01, TC-02: 정상 Incident 및 조치 2건 티켓 생성과 본문 반영"""
        inc = {
            "incident_id": "INC-TEST-001",
            "event_type": "abnormal_login",
            "severity": "HIGH",
            "target_account": "lee"
        }
        actions = [
            {"action": "block_ip", "target": "203.0.113.25", "result": "SUCCESS", "reason": "공격 차단"},
            {"action": "terminate_session", "target": "lee", "result": "SUCCESS", "reason": "세션 종료"}
        ]
        ticket = create_ticket(inc, actions)
        self.assertIn("ticket_id", ticket)
        self.assertEqual(ticket["assignee"], "security_analyst")
        self.assertIn("block_ip", ticket["body"])
        self.assertIn("terminate_session", ticket["body"])

    def test_day3_tc03_to_tc07_escalation(self):
        """TC-03 ~ TC-07: 에스컬레이션 시나리오 전체 검증"""
        ticket = {
            "ticket_id": "TICK-TC-TEST",
            "assignee": "security_analyst",
            "status": "OPEN",
            "escalated": False
        }

        # TC-03: 1차 담당자가 SLA 이내 응답 -> 발생 안 함
        r3 = check_and_escalate(ticket, elapsed_minutes=5, responded=True)
        self.assertFalse(r3["escalated"])

        # TC-04: 1차 담당자 미응답, SLA 미초과(8분 <= 10분) -> 발생 안 함
        r4 = check_and_escalate(ticket, elapsed_minutes=8, responded=False)
        self.assertFalse(r4["escalated"])

        # TC-05: 1차 담당자 미응답, SLA 초과(12분 > 10분) -> 2차 담당자에게 알림
        r5 = check_and_escalate(ticket, elapsed_minutes=12, responded=False)
        self.assertTrue(r5["escalated"])
        self.assertEqual(ticket["assignee"], "security_manager")
        self.assertEqual(ticket["status"], "ESCALATED")

        # TC-06: 이미 에스컬레이션된 티켓 재검사 -> 중복 알림 방지
        r6 = check_and_escalate(ticket, elapsed_minutes=15, responded=False)
        self.assertFalse(r6["escalated"])
        self.assertTrue(r6.get("already_escalated", False))

        # TC-07: 설정 파일의 SLA 변경 (10분 -> 3분)
        new_ticket = {"ticket_id": "TICK-TC07", "assignee": "security_analyst", "escalated": False}
        custom_rules = {"sla_minutes": 3, "enabled": True, "escalation_chain": ["security_analyst", "security_manager"]}
        r7 = check_and_escalate(new_ticket, elapsed_minutes=5, responded=False, rules=custom_rules)
        self.assertTrue(r7["escalated"])

if __name__ == "__main__":
    unittest.main()
