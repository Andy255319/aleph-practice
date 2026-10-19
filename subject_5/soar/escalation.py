import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from soar.ticketing import sync_ticket_status, get_ticket

def _get_rules_path() -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "config", "escalation_rules.json")

def load_escalation_rules() -> Dict[str, Any]:
    with open(_get_rules_path(), "r", encoding="utf-8") as f:
        return json.load(f)

def send_alert(channel: str, recipient: str, title: str, message: str) -> Dict[str, Any]:
    """1과목 알림 연동 함수 (모의 Slack/Webhook/Email 발송)"""
    alert_payload = {
        "timestamp": datetime.now().isoformat(),
        "channel": channel,
        "recipient": recipient,
        "title": title,
        "message": message,
        "delivery_status": "DELIVERED"
    }
    # 실제 환경에서는 requests.post(webhook_url, json=payload)
    return alert_payload

class EscalationManager:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules = load_escalation_rules()
        self.tiers = self.rules.get("escalation_policy", {}).get("tiers", [])

    def get_tier_info(self, tier: int) -> Optional[Dict[str, Any]]:
        for t in self.tiers:
            if t["tier"] == tier:
                return t
        return None

    def escalate(
        self,
        ticket_id: str,
        current_tier: int,
        reason: str,
        simulated_elapsed_minutes: Optional[int] = None
    ) -> Dict[str, Any]:
        """SLA 초과 또는 1차 담당자 무응답 시 상위 티어로 에스컬레이션 수행"""
        curr_tier_info = self.get_tier_info(current_tier)
        next_tier = current_tier + 1
        next_tier_info = self.get_tier_info(next_tier)

        if not next_tier_info:
            return {
                "ticket_id": ticket_id,
                "escalated": False,
                "message": f"최상위 티어({current_tier})에 이미 도달하여 추가 에스컬레이션이 불가능합니다."
            }

        sla_timeout = curr_tier_info.get("sla_timeout_minutes", 15) if curr_tier_info else 15
        elapsed = simulated_elapsed_minutes if simulated_elapsed_minutes is not None else sla_timeout + 1

        escalation_comment = (
            f"[SLA 에스컬레이션 발동] Tier-{current_tier} ({curr_tier_info.get('role')}) 경과시간 {elapsed}분 > SLA {sla_timeout}분. "
            f"사유: {reason}. 담당자를 Tier-{next_tier} ({next_tier_info.get('role')}: {next_tier_info.get('primary_contact')})로 이관합니다."
        )

        # 티켓 상태 및 담당자 업데이트
        ticket = get_ticket(ticket_id)
        if ticket:
            ticket["assignee"] = next_tier_info["primary_contact"]
            sync_ticket_status(ticket_id, "ESCALATED", escalation_comment, operator="ESCALATION_ENGINE")

        # 상위 담당자 채널에 긴급 알림 전송 (1과목 알림 함수 연동)
        alert = send_alert(
            channel=next_tier_info.get("slack_channel", "#secops"),
            recipient=next_tier_info.get("primary_contact", "secops@company.internal"),
            title=f"🚨 [긴급 에스컬레이션] {ticket_id} 대응 이관 (Tier-{next_tier})",
            message=escalation_comment
        )

        return {
            "ticket_id": ticket_id,
            "escalated": True,
            "previous_tier": current_tier,
            "new_tier": next_tier,
            "new_assignee": next_tier_info["primary_contact"],
            "sla_timeout_minutes": sla_timeout,
            "elapsed_minutes": elapsed,
            "reason": reason,
            "alert_sent": alert
        }


def escalate(
    ticket_id: str,
    current_tier: int,
    reason: str,
    simulated_elapsed_minutes: Optional[int] = None
) -> Dict[str, Any]:
    mgr = EscalationManager()
    return mgr.escalate(ticket_id, current_tier, reason, simulated_elapsed_minutes)
