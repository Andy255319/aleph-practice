"""
SOAR Response 통합 시뮬레이션 및 실습 실행 스크립트 (Day 1 ~ Day 4 슬라이드 규격 반영)
"""
import sys
import os
import json
from datetime import datetime

# Windows 콘솔 한글/유니코드 인코딩 설정
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# 패키지 경로 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from soar.incident import Incident, update_status, match_playbook
from soar.containment import (
    lock_account,
    unlock_account,
    block_ip,
    unblock_ip,
    terminate_session,
    is_vip_account,
    VIPApprovalRequired,
    get_all_containment_logs
)
from soar.ticketing import create_ticket, sync_ticket_status, get_ticket
from soar.escalation import check_and_escalate, load_escalation_rules
from soar.approval_gate import execute_action, handle_false_positive
from soar.report import generate_reports

def run_day1_flow():
    print("\n" + "="*75)
    print("▶ [DAY 1] 플레이북 템플릿 설계 및 4단계 흐름 (슬라이드 명세 반영)")
    print("="*75)

    # 1. 슬라이드 규격 인시던트 생성 (event_id="evt-2001", status="detected")
    inc = Incident(
        incident_id="evt-2001",
        event_type="ABNORMAL_LOGIN",
        severity="HIGH",
        source_ip="203.0.113.25",
        target_account="lee",
        description="비정상 로그인 탐지",
        raw_log={"src_ip": "203.0.113.25", "account": "lee", "status": "FAIL"}
    )
    print(f"[1-1] 인시던트 생성: event_id={inc.event_id}, status={inc.status}")

    # 2. 플레이북 레지스트리(config/playbook_registry.json) 매칭 테스트
    pb_login = match_playbook("ABNORMAL_LOGIN")
    pb_traffic = match_playbook("TRAFFIC_SPIKE")
    pb_corr = match_playbook("CORRELATED_ATTACK")
    inc.matched_playbook = pb_login

    print(f"[1-2] 플레이북 레지스트리 매칭 결과:")
    print(f"      - ABNORMAL_LOGIN    -> {pb_login['id']} (대응 수준: {pb_login['response_level']})")
    print(f"      - TRAFFIC_SPIKE     -> {pb_traffic['id']} (대응 수준: {pb_traffic['response_level']})")
    print(f"      - CORRELATED_ATTACK -> {pb_corr['id']} (대응 수준: {pb_corr['response_level']})")

    # 3. update_status()로 status를 triaged로 변경하고 history 확인 출력
    print(f"\n[1-3] update_status() 실행 (detected -> triaged 전이 및 history 추가):")
    update_status(inc, "triaged", "위험도 분석 및 분류 완료")

    return inc


def run_day2_flow():
    print("\n" + "="*75)
    print("▶ [DAY 2] 계정잠금·접근차단 자동화 스크립트 구현 (슬라이드 명세 테스트 시나리오)")
    print("="*75)

    recorded_actions = []

    # 시나리오 A: 일반 계정 자동 잠금
    print("[2-1] 시나리오 A: 일반 계정 자동 잠금")
    print("      - 계정: lee, 사유: 비정상 로그인 반복")
    act_a = lock_account("lee", "비정상 로그인 반복")
    recorded_actions.append(act_a)
    print(f"      -> 결과: {act_a['result']} | 대상: {act_a['target']} | 사유: {act_a['reason']}")

    # 시나리오 B: VIP 계정 승인 필요
    print("\n[2-2] 시나리오 B: VIP 계정 승인 필요")
    print("      - 계정: kim, 사유: 계정 탈취 의심")
    try:
        lock_account("kim", "계정 탈취 의심")
    except VIPApprovalRequired as e:
        print(f"      -> [예외 포착 및 처리]: {e}")
        print("      -> 자동 잠금 대신 승인 필요 메시지 출력 및 승인 필요 이력 기록 완료")

    # 시나리오 C: IP 차단과 세션 종료
    print("\n[2-3] 시나리오 C: IP 차단과 세션 종료 결합")
    print("      - IP: 203.0.113.25, 계정: lee, 사유: 악성 IP에서 비정상 로그인 탐지")
    act_c1 = block_ip("203.0.113.25", "악성 IP에서 비정상 로그인 탐지")
    act_c2 = terminate_session("lee", "악성 IP에서 비정상 로그인 탐지")
    recorded_actions.extend([act_c1, act_c2])
    print(f"      -> IP 차단 결과: {act_c1['result']} | {act_c1['reason']}")
    print(f"      -> 세션 종료 결과: {act_c2['result']} | {act_c2['reason']}")

    # 5. 추가 테스트 (해제 및 예외 상황)
    print("\n[2-4] 추가 테스트: 차단 해제 및 사유 누락/중복 처리 검증")
    # 사유 누락 테스트
    fail_unlock = unlock_account("lee", "")
    print(f"      - 사유 누락 잠금 해제 시도: 결과 = {fail_unlock['result']} ({fail_unlock['reason']})")
    # 정상 해제
    ok_unlock = unlock_account("lee", "관제 분석 완료 후 정상 복구")
    print(f"      - 정상 잠금 해제: 결과 = {ok_unlock['result']} ({ok_unlock['reason']})")
    # 이미 해제된 대상 재해제
    skip_unlock = unlock_account("lee", "재해제 시도")
    print(f"      - 이미 해제된 계정 재해제: 결과 = {skip_unlock['result']} ({skip_unlock['reason']})")

    # IP 정상 해제
    ok_unblock = unblock_ip("203.0.113.25", "공격 소멸 확인 후 방화벽 롤백")
    print(f"      - 정상 IP 차단 해제: 결과 = {ok_unblock['result']} ({ok_unblock['reason']})")

    return recorded_actions

def run_day3_flow(inc: Incident, containment_actions: list):
    print("\n" + "="*75)
    print("▶ [DAY 3] 티켓 생성·알림·에스컬레이션 워크플로우 (TC-01 ~ TC-07 시뮬레이션)")
    print("="*75)

    # TC-01: 정상 Incident 입력 -> 티켓 생성 성공
    # TC-02: 조치 결과 2건 입력 -> 두 조치 모두 티켓 본문에 반영
    ticket = create_ticket(incident=inc, action_results=containment_actions[:2])
    print(f"[TC-01 / TC-02] 티켓 생성 완료: {ticket['ticket_id']}")
    print(f"  - 제목: {ticket['title']}")
    print(f"  - 초기 담당자: {ticket['assignee']} (1차)")
    print(f"  - 티켓 본문 조치 반영 건수: {len(ticket['action_results'])}건")

    # TC-03: 1차 담당자가 SLA 이내 응답 -> 에스컬레이션 발생 안 함
    tc03 = check_and_escalate(ticket, elapsed_minutes=5, responded=True)
    print(f"[TC-03] 1차 담당자 5분 내 응답 시: 에스컬레이션 발생 = {tc03['escalated']} ({tc03['reason']})")

    # TC-04: 1차 담당자 미응답, SLA 미초과 -> 에스컬레이션 발생 안 함
    tc04 = check_and_escalate(ticket, elapsed_minutes=8, responded=False)
    print(f"[TC-04] 미응답 8분 경과 (SLA 10분): 에스컬레이션 발생 = {tc04['escalated']} ({tc04['reason']})")

    # TC-05: 1차 담당자 미응답, SLA 초과 -> 2차 담당자에게 알림
    tc05 = check_and_escalate(ticket, elapsed_minutes=15, responded=False)
    print(f"[TC-05] 미응답 15분 경과 (SLA 초과): 에스컬레이션 발생 = {tc05['escalated']}")
    print(f"  - 변경된 담당자: {tc05['new_assignee']} (2차)")
    print(f"  - 발송된 알림: {tc05['notification']['message']}")

    # TC-06: 이미 에스컬레이션된 티켓 재검사 -> 중복 알림 방지
    tc06 = check_and_escalate(ticket, elapsed_minutes=20, responded=False)
    print(f"[TC-06] 이미 에스컬레이션된 티켓 재검사: 에스컬레이션 발생 = {tc06['escalated']} ({tc06['reason']})")

    # TC-07: 설정 파일의 SLA 변경 -> 변경된 SLA 기준 적용
    custom_rules = {"sla_minutes": 5, "enabled": True, "escalation_chain": ["security_analyst", "security_manager"]}
    fresh_ticket = create_ticket(incident=inc, action_results=containment_actions[:1])
    tc07 = check_and_escalate(fresh_ticket, elapsed_minutes=6, responded=False, rules=custom_rules)
    print(f"[TC-07] 변경된 SLA(5분) 적용 시: 경과 6분 -> 에스컬레이션 발생 = {tc07['escalated']} ({tc07['reason']})")

    # 상태 동기화 검증
    update_status(inc, "CONTAINMENT", "격리 및 에스컬레이션 진행", operator="SOAR_ENGINE")
    sync_ticket_status(inc, ticket)
    print(f"  - 인시던트({inc.status})와 티켓 상태 동기화 결과: 티켓 상태 = {ticket['status']}")

    return ticket

def run_day4_flow(inc: Incident, ticket: dict):
    print("\n" + "="*75)
    print("▶ [DAY 4] 초동대응 리포트·승인게이트·오탐대응 절차 시뮬레이션")
    print("="*75)

    # 1. 승인 게이트 분기
    gate_res = execute_action("terminate_session", "lee", {"reason": "자동화 세션 종료"})
    print(f"[4-1] 공통 승인 게이트 (Low 위험도): {gate_res['action_type']} -> 상태: {gate_res['status']}")

    # 2. 오탐 복구
    fp_res = handle_false_positive(
        incident_id="INC-20261019-FP",
        target_account="kim",
        target_ip="203.0.113.25",
        fp_reason="VIP 임원 모바일 테더링 정상 접속 확인"
    )
    print(f"[4-2] 오탐 복구(handle_false_positive): 결과 = {fp_res['status']}")
    print(f"  - 4과목 학습셋 라벨 적재: {fp_res['labeled_data_recorded']['ground_truth_label']}")

    # 3. 기술팀/경영진용 2종 리포트 생성
    reports = generate_reports(incident_data=inc.to_dict(), ticket_id=ticket["ticket_id"])
    print(f"[4-3] 2종 초동대응 리포트 생성 완료:")
    print(f"  - 기술팀 상세 리포트: {reports['technical_report']}")
    print(f"  - 경영진 요약 리포트: {reports['executive_report']}")

    print("\n" + "="*75)
    print("[SUCCESS] 5과목 전체 실습 파이프라인 (슬라이드 규격 반영) 실행 및 산출물 갱신 완료!")
    print("="*75 + "\n")

if __name__ == "__main__":
    inc = run_day1_flow()
    actions = run_day2_flow()
    t = run_day3_flow(inc, actions)
    run_day4_flow(inc, t)
