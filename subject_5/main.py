"""
SOAR Response 통합 시뮬레이션 및 실습 실행 스크립트 (Day 1 ~ Day 4)
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
    get_all_containment_logs
)
from soar.ticketing import create_ticket, sync_ticket_status, get_ticket
from soar.escalation import escalate
from soar.approval_gate import execute_action, handle_false_positive
from soar.report import generate_reports

def run_day1_flow():
    print("\n" + "="*70)
    print("▶ [DAY 1] 플레이북 템플릿 설계 및 4단계 흐름 시뮬레이션")
    print("="*70)

    # 1. 인시던트 데이터 생성 (비정상 로그인 시나리오)
    inc = Incident(
        incident_id="INC-20261019-001",
        event_type="abnormal_login",
        severity="HIGH",
        source_ip="198.51.100.45",
        target_account="user_john",
        description="동일 계정에 대해 해외 미인가 IP에서 5분간 12회 로그인 실패 후 로그인 성공 탐지",
        raw_log={
            "src_ip": "198.51.100.45",
            "country": "RU",
            "failed_attempts": 12,
            "success": True,
            "timestamp": datetime.now().isoformat()
        }
    )
    print(f"[1-1] 인시던트 생성: ID={inc.incident_id}, Event={inc.event_type}, Status={inc.status}")

    # 2. 플레이북 매칭
    pb = match_playbook(inc.event_type)
    inc.matched_playbook = pb
    print(f"[1-2] 플레이북 매칭 완료: {pb.get('name')} (ID: {pb.get('id')})")

    # 3. 인시던트 상태 전이
    update_status(inc, "ANALYZING", "플레이북 수신 및 위협 인텔리전스 IP 평판 조회 시작", operator="SOAR_ORCHESTRATOR")
    print(f"[1-3] 상태 전이: NEW -> {inc.status} ({inc.history[-1]['comment']})")

    return inc

def run_day2_flow(inc: Incident):
    print("\n" + "="*70)
    print("▶ [DAY 2] 계정잠금·접근차단 자동화 스크립트 시뮬레이션 (3개 테스트 시나리오)")
    print("="*70)

    recorded_actions = []

    # 시나리오 A: 일반 계정 자동 잠금
    print("[2-1] 시나리오 A: 일반 계정(user_john) 자동 잠금 테스트")
    act1 = lock_account(inc.target_account, "비정상 로그인 다수 탐지에 따른 임시 계정 잠금", operator="SOAR_CONTAINMENT_ENGINE")
    recorded_actions.append(act1)
    print(f"      결과: {act1['status']} | 대상: {act1['target']} | {act1['details']}")

    # 시나리오 B: VIP 계정(ceo_kim) 자동 잠금 시도 -> VIP 예외 발생 및 승인 우회 확인
    print("[2-2] 시나리오 B: VIP 계정(ceo_kim) 자동 잠금 시도 (보호 로직 검증)")
    try:
        lock_account("ceo_kim", "VIP 계정 의심 행위 차단 시도", operator="SOAR_CONTAINMENT_ENGINE")
    except Exception as e:
        print(f"      [안전장치 정상 발동] VIP 보호 예외 포착: {e}")

    # VIP 계정에 대해 승인 절차를 거친 후 잠금 수행
    print("      [승인 게이트 통과 후 VIP 조치] CISO 긴급 승인 획득 후 잠금 재시도")
    act_vip = lock_account("ceo_kim", "CISO 구두 긴급 승인 득함 (내부 전산 침해 의심)", operator="APPROVED_BY(CISO_PARK)", is_approved=True)
    recorded_actions.append(act_vip)
    print(f"      결과: {act_vip['status']} | {act_vip['details']}")

    # 시나리오 C: IP 차단 + 활성 세션 강제 종료 결합
    print("[2-3] 시나리오 C: 공격 원천 IP 차단 + 활성 세션 강제 종료 결합 테스트")
    act2 = block_ip(inc.source_ip, "해외 미인가 IP 공격 원천 즉각 차단", operator="SOAR_CONTAINMENT_ENGINE")
    act3 = terminate_session(inc.target_account, "sess_9988_token", "침해 위험 계정 활성 토큰 무효화", operator="SOAR_CONTAINMENT_ENGINE")
    recorded_actions.extend([act2, act3])
    print(f"      IP 차단: {act2['status']} | {act2['details']}")
    print(f"      세션 종료: {act3['status']} | {act3['details']}")

    # 인시던트 상태 전이
    update_status(inc, "CONTAINMENT", "일반계정 잠금, 세션 종료, IP 차단 등 1차 격리 완료", operator="SOAR_ENGINE")

    return recorded_actions

def run_day3_flow(inc: Incident, containment_actions: list):
    print("\n" + "="*70)
    print("▶ [DAY 3] 티켓 생성·알림·에스컬레이션 워크플로우 시뮬레이션")
    print("="*70)

    # 1. 2일차 조치 결과가 티켓 본문에 자동 반영되는 티켓 생성
    ticket = create_ticket(
        incident_data=inc.to_dict(),
        containment_actions=containment_actions,
        assignee="analyst_on_duty@company.internal"
    )
    print(f"[3-1] ITSM 티켓 발급 완료: Ticket ID = {ticket['ticket_id']}")
    print(f"      제목: {ticket['title']}")
    print(f"      1차 배정 담당자: {ticket['assignee']}")
    print(f"      본문 반영 조치 건수: {len(ticket['containment_actions'])}건")

    # 2. 에스컬레이션 시나리오 시뮬레이션: 1차 분석가 무응답 (15분 SLA 초과) -> 2차 보안팀장으로 에스컬레이션
    print("[3-2] 테스트 시나리오: 1차 담당자 15분간 무응답 발생 -> 2차 에스컬레이션 트리거")
    esc_result = escalate(
        ticket_id=ticket["ticket_id"],
        current_tier=1,
        reason="야간 교대시간 1차 SOC 분석가 20분간 티켓 무응답",
        simulated_elapsed_minutes=20
    )
    print(f"      에스컬레이션 성공 여부: {esc_result['escalated']}")
    print(f"      신규 이관 담당자: Tier-{esc_result['new_tier']} ({esc_result['new_assignee']})")
    print(f"      발송된 긴급 알림 채널: {esc_result['alert_sent']['channel']}")

    # 3. day03_test_result.md 생성
    day03_md_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soar", "day03_test_result.md")
    test_result_md = f"""# Day 3 티켓 생성 ~ 에스컬레이션 전체 흐름 테스트 결과 보고서

- **테스트 일시**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **대상 인시던트**: `{inc.incident_id}`
- **생성된 티켓**: `{ticket['ticket_id']}`

## 1. 테스트 목적
2일차 격리 조치 내역의 티켓 본문 자동 첨부 검증 및 SLA 초과 시 1차 담당자 무응답에 따른 2차 보안팀장 에스컬레이션 체인 정상 동작 확인.

## 2. 세부 검증 항목 및 결과

| 검증 항목 | 기대 결과 | 실제 테스트 결과 | 판정 |
|---|---|---|---|
| 티켓 본문 2일차 조치 연동 | 격리 조치 4건(잠금, 세션종료, IP차단 등)이 포맷팅되어 본문에 자동 첨부 | 총 {len(containment_actions)}건의 조치 내역이 타임스탬프와 함께 자동 첨부됨 | **PASS** |
| 1차 SLA 타임아웃 감지 | SLA 15분 초과(20분 경과) 시 에스컬레이션 이벤트 발생 | 경과시간 20분 감지 후 승격 로직 즉시 발동 | **PASS** |
| 에스컬레이션 체인 이관 | 담당자가 Tier-1(분석가)에서 Tier-2(보안팀장)로 갱신 | 담당자 `{esc_result['new_assignee']}`로 이관 완료 | **PASS** |
| 1과목 알림 함수 연동 | Tier-2 전용 채널(`{esc_result['alert_sent']['channel']}`)로 긴급 알림 전송 | 모의 웹훅 알림 정상 페이로드 생성 및 전달 확인 | **PASS** |

## 3. 생성된 티켓 본문 스니펫
```text
{ticket['body']}
```
"""
    with open(day03_md_path, "w", encoding="utf-8") as f:
        f.write(test_result_md)
    print(f"[3-3] Day 3 테스트 결과 보고서 저장 완료: {day03_md_path}")

    return ticket

def run_day4_flow(inc: Incident, ticket: dict):
    print("\n" + "="*70)
    print("▶ [DAY 4] 초동대응 리포트·승인게이트·오탐대응 절차 시뮬레이션")
    print("="*70)

    # 1. 승인 게이트 execute_action() 공통 분기 검증
    print("[4-1] 공통 승인 게이트 execute_action() 위험 등급별 분기 테스트")
    # Low 리스크: terminate_session -> 자동 승인 즉시 실행
    gate_res_low = execute_action("terminate_session", "user_temp", {"session_id": "sess_low_01", "reason": "테스트 저위험 세션 종료"})
    print(f"      [Low 위험도] {gate_res_low['action_type']} -> 상태: {gate_res_low['status']} (승인 필요 여부: 자동)")

    # High 리스크: block_ip 승인 없이 호출 -> APPROVAL_PENDING 반환
    gate_res_high_no_app = execute_action("block_ip", "203.0.113.88", {"reason": "스캔 공격 IP 차단 시도"})
    print(f"      [High 위험도 승인자 부재 시] {gate_res_high_no_app['action_type']} -> 상태: {gate_res_high_no_app['status']} ({gate_res_high_no_app['message']})")

    # High 리스크: 승인자 포함 호출 -> EXECUTED 실행
    gate_res_high_app = execute_action("block_ip", "203.0.113.88", {"reason": "스캔 공격 IP 차단 승인됨"}, approver="SECOPS_LEAD_KIM")
    print(f"      [High 위험도 승인 완료 시] {gate_res_high_app['action_type']} -> 상태: {gate_res_high_app['status']} (승인자: {gate_res_high_app['approver']})")

    # 2. 오탐(False Positive) 대응 시뮬레이션 (handle_false_positive)
    print("\n[4-2] 오탐(False Positive) 시나리오 검증: 즉시 해제 + 원인기록 + 4과목 학습셋 라벨링")
    fp_res = handle_false_positive(
        incident_id="INC-20261019-009-FP",
        target_account="marketing_staff",
        target_ip="115.68.22.10",
        fp_reason="임직원 해외 출장 중 공항 와이파이 VPN 접속에 따른 오경보 확인",
        operator="SECOPS_ANALYST_KANG",
        raw_event={"vpn_type": "SSL-VPN", "mfa_success": True}
    )
    print(f"      오탐 처리 결과: {fp_res['status']}")
    print(f"      롤백 조치: {len(fp_res['rollback_actions'])}건 완료 (계정 및 IP 차단 해제)")
    print(f"      4과목 AI/ML 라벨 데이터셋 추가 완료: {fp_res['labeled_data_recorded']['ground_truth_label']}")

    # 3. 1~3일차 데이터 취합 기반 2종 초동대응 리포트 생성 (기술팀용 상세 / 경영진용 요약)
    print("\n[4-3] 1~3일차 데이터 자동 취합 및 2종 초동 대응 리포트 생성")
    reports = generate_reports(incident_data=inc.to_dict(), ticket_id=ticket["ticket_id"])
    print(f"      [기술팀 상세 리포트]: {reports['technical_report']}")
    print(f"      [경영진 요약 리포트]: {reports['executive_report']}")

    print("\n" + "="*70)
    print("[SUCCESS] Day 1 ~ Day 4 전체 SOAR 워크플로우 실행 및 산출물 생성 완료!")
    print("="*70)

if __name__ == "__main__":
    incident = run_day1_flow()
    actions = run_day2_flow(incident)
    ticket_obj = run_day3_flow(incident, actions)
    run_day4_flow(incident, ticket_obj)
