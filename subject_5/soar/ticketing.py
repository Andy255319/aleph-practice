"""
Day 3: 티켓 생성 및 상태 동기화 모듈
"""
import os
import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

def _get_base_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _get_escalation_rules() -> Dict[str, Any]:
    rules_path = os.path.join(_get_base_dir(), "config", "escalation_rules.json")
    if os.path.exists(rules_path):
        with open(rules_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "sla_minutes": 10,
        "enabled": True,
        "escalation_chain": ["security_analyst", "security_manager"]
    }

class MockTicketStore:
    _tickets: Dict[str, Dict[str, Any]] = {}

def create_ticket(
    incident: Any,
    action_results: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Incident 정보와 조치 결과를 이용해 티켓을 생성한다.
    필수 필드: ticket_id, event_id, title, status, assignee, body, created_at
    """
    rules = _get_escalation_rules()
    chain = rules.get("escalation_chain", ["security_analyst", "security_manager"])
    initial_assignee = chain[0] if chain else "security_analyst"

    # Incident 객체 또는 Dict 처리
    if hasattr(incident, "to_dict"):
        inc_data = incident.to_dict()
    elif isinstance(incident, dict):
        inc_data = incident
    else:
        inc_data = {"incident_id": str(incident)}

    event_id = inc_data.get("event_id") or inc_data.get("incident_id", "EVT-UNKNOWN")
    ticket_id = f"TICK-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
    title = f"[{inc_data.get('severity', 'HIGH')}] {inc_data.get('event_type', '보안 위협')} 대응 요청 - {inc_data.get('target_account', inc_data.get('target', 'Target'))}"

    # 사건 정보와 조치 결과 2건 이상 모두 티켓 본문에 포맷팅
    body_lines = [
        "=== 보안 인시던트 세부 정보 ===",
        f"이벤트 ID: {event_id}",
        f"공격 유형: {inc_data.get('event_type', 'N/A')}",
        f"위협 등급: {inc_data.get('severity', 'HIGH')}",
        f"출발지 IP: {inc_data.get('source_ip', 'N/A')}",
        f"대상 계정: {inc_data.get('target_account', 'N/A')}",
        f"상세 내용: {inc_data.get('description', 'N/A')}",
        "",
        "=== 격리 조치 결과 (Containment Actions) ==="
    ]

    action_list = action_results or []
    if action_list:
        for idx, act in enumerate(action_list, 1):
            body_lines.append(
                f"[{idx}] 조치: {act.get('action')} | 대상: {act.get('target')} | 결과: {act.get('result')} | 사유: {act.get('reason')}"
            )
    else:
        body_lines.append("조치 결과 없음")

    body_text = "\n".join(body_lines)

    ticket = {
        "ticket_id": ticket_id,
        "event_id": event_id,
        "title": title,
        "status": "OPEN",
        "assignee": initial_assignee,
        "body": body_text,
        "created_at": datetime.now().isoformat(),
        # 부가 메타데이터
        "escalated": False,
        "escalation_count": 0,
        "action_results": action_list
    }

    MockTicketStore._tickets[ticket_id] = ticket
    return ticket

def sync_ticket_status(incident: Any, ticket: Dict[str, Any]) -> Dict[str, Any]:
    """
    Incident 상태와 티켓 상태를 미리 정한 규칙에 따라 동기화한다:
    - Incident CLOSED -> Ticket RESOLVED
    - Incident CONTAINMENT -> Ticket IN_PROGRESS
    - Incident FALSE_POSITIVE -> Ticket CANCELLED
    - Incident ESCALATED -> Ticket ESCALATED
    - Incident ANALYZING / NEW -> Ticket OPEN
    """
    if hasattr(incident, "status"):
        inc_status = incident.status
    elif isinstance(incident, dict):
        inc_status = incident.get("status", "NEW")
    else:
        inc_status = str(incident)

    status_mapping = {
        "NEW": "OPEN",
        "ANALYZING": "OPEN",
        "CONTAINMENT": "IN_PROGRESS",
        "APPROVAL_PENDING": "PENDING_APPROVAL",
        "ESCALATED": "ESCALATED",
        "CLOSED": "RESOLVED",
        "FALSE_POSITIVE": "CANCELLED"
    }

    new_ticket_status = status_mapping.get(inc_status, ticket.get("status", "OPEN"))
    ticket["status"] = new_ticket_status
    ticket["updated_at"] = datetime.now().isoformat()
    return ticket

def get_ticket(ticket_id: str) -> Optional[Dict[str, Any]]:
    return MockTicketStore._tickets.get(ticket_id)
