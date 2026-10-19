"""
Day 3: 알림 및 SLA 에스컬레이션 워크플로우 모듈
"""
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional, List

def _get_base_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_escalation_rules(custom_path: Optional[str] = None) -> Dict[str, Any]:
    rules_path = custom_path or os.path.join(_get_base_dir(), "config", "escalation_rules.json")
    if os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "sla_minutes": 10,
        "enabled": True,
        "escalation_chain": ["security_analyst", "security_manager"]
    }

def send_notification(recipient: str, message: str) -> Dict[str, Any]:
    """2차 담당자 알림 전송 (Slack/Webhook/Email 모의)"""
    return {
        "recipient": recipient,
        "message": message,
        "sent_at": datetime.now().isoformat(),
        "status": "SENT"
    }

def check_and_escalate(
    ticket: Dict[str, Any],
    elapsed_minutes: int,
    responded: bool = False,
    rules: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    SLA 제한 시간 및 1차 담당자 응답 여부에 따른 에스컬레이션 판정 및 실행:
    - TC-03: 1차 담당자가 SLA 이내 응답 -> 에스컬레이션 발생 안 함
    - TC-04: 1차 담당자 미응답, SLA 미초과 -> 에스컬레이션 발생 안 함
    - TC-05: 1차 담당자 미응답, SLA 초과 -> 2차 담당자에게 알림 및 이관
    - TC-06: 이미 에스컬레이션된 티켓 재검사 -> 중복 알림 방지
    - TC-07: 설정 파일의 SLA 변경 -> 변경된 SLA 기준 적용
    """
    if rules is None:
        rules = load_escalation_rules()

    enabled = rules.get("enabled", True)
    sla_minutes = rules.get("sla_minutes", 10)
    chain = rules.get("escalation_chain", ["security_analyst", "security_manager"])

    ticket_id = ticket.get("ticket_id", "UNKNOWN")

    # 1. 에스컬레이션 비활성화된 경우
    if not enabled:
        return {
            "ticket_id": ticket_id,
            "escalated": False,
            "reason": "에스컬레이션 기능 비활성화됨"
        }

    # 2. TC-06: 이미 에스컬레이션된 티켓 재검사 (중복 알림 방지)
    if ticket.get("escalated", False):
        return {
            "ticket_id": ticket_id,
            "escalated": False,
            "already_escalated": True,
            "reason": "이미 에스컬레이션된 티켓으로 중복 알림 방지"
        }

    # 3. TC-03: 1차 담당자가 응답한 경우
    if responded:
        return {
            "ticket_id": ticket_id,
            "escalated": False,
            "reason": "1차 담당자가 SLA 이내 정상 응답함"
        }

    # 4. TC-04: 1차 담당자 미응답이나 SLA 시간 미초과인 경우
    if elapsed_minutes <= sla_minutes:
        return {
            "ticket_id": ticket_id,
            "escalated": False,
            "elapsed_minutes": elapsed_minutes,
            "sla_minutes": sla_minutes,
            "reason": f"SLA 제한시간({sla_minutes}분) 미초과 (경과: {elapsed_minutes}분)"
        }

    # 5. TC-05 / TC-07: 미응답 및 SLA 초과 -> 2차 담당자에게 알림 및 승격
    next_assignee = chain[1] if len(chain) > 1 else "security_manager"
    prev_assignee = ticket.get("assignee", chain[0])

    notification_msg = (
        f"[긴급 SLA 초과 에스컬레이션] 티켓 {ticket_id} 1차 담당자({prev_assignee}) {elapsed_minutes}분간 미응답 (SLA: {sla_minutes}분). "
        f"2차 담당자({next_assignee})에게 이관합니다."
    )
    notif = send_notification(recipient=next_assignee, message=notification_msg)

    # 티켓 상태 업데이트
    ticket["assignee"] = next_assignee
    ticket["status"] = "ESCALATED"
    ticket["escalated"] = True
    ticket["escalation_count"] = ticket.get("escalation_count", 0) + 1
    ticket["last_escalated_at"] = datetime.now().isoformat()

    return {
        "ticket_id": ticket_id,
        "escalated": True,
        "previous_assignee": prev_assignee,
        "new_assignee": next_assignee,
        "elapsed_minutes": elapsed_minutes,
        "sla_minutes": sla_minutes,
        "notification": notif,
        "reason": f"SLA 초과({elapsed_minutes}분 > {sla_minutes}분) 및 1차 담당자 미응답"
    }

def escalate(
    ticket_id: str,
    current_tier: int = 1,
    reason: str = "",
    simulated_elapsed_minutes: Optional[int] = None
) -> Dict[str, Any]:
    """기존 코드 호환용 래퍼"""
    from soar.ticketing import get_ticket
    ticket = get_ticket(ticket_id) or {"ticket_id": ticket_id}
    elapsed = simulated_elapsed_minutes if simulated_elapsed_minutes is not None else 15
    res = check_and_escalate(ticket, elapsed_minutes=elapsed, responded=False)
    # 기존 인터페이스 포맷 매핑
    return {
        "ticket_id": ticket_id,
        "escalated": res.get("escalated", False),
        "new_tier": 2,
        "new_assignee": res.get("new_assignee", "security_manager"),
        "alert_sent": {"channel": "#soc-lead", "recipient": res.get("new_assignee", "security_manager")}
    }
