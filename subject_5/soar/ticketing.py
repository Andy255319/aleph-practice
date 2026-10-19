import json
import os
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

class MockTicketingSystem:
    """모의 ITSM / Jira 티켓 관리 시스템"""
    _tickets: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def create_ticket(
        cls,
        incident_data: Dict[str, Any],
        containment_actions: Optional[List[Dict[str, Any]]] = None,
        assignee: str = "analyst_on_duty@company.internal"
    ) -> Dict[str, Any]:
        ticket_id = f"SEC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"
        
        # 2일차 조치 결과 자동 본문 반영
        action_summary = "조치 내역 없음"
        if containment_actions:
            action_lines = []
            for act in containment_actions:
                action_lines.append(
                    f"- [{act.get('timestamp')}] {act.get('action_type')} (대상: {act.get('target')}) "
                    f"-> 상태: {act.get('status')} | 상세: {act.get('details')}"
                )
            action_summary = "\n".join(action_lines)

        body = (
            f"=== 보안 침해사고 긴급 대응 티켓 ===\n"
            f"인시던트 ID: {incident_data.get('incident_id')}\n"
            f"이벤트 유형: {incident_data.get('event_type')}\n"
            f"위험도(심각도): {incident_data.get('severity')}\n"
            f"출발지 IP: {incident_data.get('source_ip')}\n"
            f"대상 계정: {incident_data.get('target_account')}\n"
            f"사고 설명: {incident_data.get('description')}\n\n"
            f"=== 2일차 SOAR 자동 격리 조치 내역 ===\n"
            f"{action_summary}\n\n"
            f"=== 대응 가이드라인 ===\n"
            f"플레이북 지침에 따라 15분 내 초동 분석 완료 및 추가 조치 승인 필요."
        )

        ticket = {
            "ticket_id": ticket_id,
            "incident_id": incident_data.get("incident_id"),
            "title": f"[{incident_data.get('severity')}] {incident_data.get('event_type')} 침해 경보 - {incident_data.get('target_account')}",
            "body": body,
            "status": "OPEN",
            "priority": incident_data.get("severity", "MEDIUM"),
            "assignee": assignee,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "worklogs": [
                {
                    "timestamp": datetime.now().isoformat(),
                    "author": "SOAR_BOT",
                    "comment": "플레이북에 의한 자동 티켓 생성 및 조치 내역 첨부 완료"
                }
            ],
            "containment_actions": containment_actions or []
        }

        cls._tickets[ticket_id] = ticket
        return ticket

    @classmethod
    def sync_ticket_status(
        cls,
        ticket_id: str,
        new_status: str,
        worklog: Optional[str] = None,
        operator: str = "SOAR_SYSTEM"
    ) -> Dict[str, Any]:
        if ticket_id not in cls._tickets:
            raise KeyError(f"티켓을 찾을 수 없습니다: {ticket_id}")

        ticket = cls._tickets[ticket_id]
        ticket["status"] = new_status
        ticket["updated_at"] = datetime.now().isoformat()
        if worklog:
            ticket["worklogs"].append({
                "timestamp": datetime.now().isoformat(),
                "author": operator,
                "comment": worklog
            })
        return ticket

    @classmethod
    def get_ticket(cls, ticket_id: str) -> Optional[Dict[str, Any]]:
        return cls._tickets.get(ticket_id)

    @classmethod
    def get_all_tickets(cls) -> List[Dict[str, Any]]:
        return list(cls._tickets.values())


def create_ticket(
    incident_data: Dict[str, Any],
    containment_actions: Optional[List[Dict[str, Any]]] = None,
    assignee: str = "analyst_on_duty@company.internal"
) -> Dict[str, Any]:
    """티켓 생성 함수 래퍼"""
    return MockTicketingSystem.create_ticket(incident_data, containment_actions, assignee)

def sync_ticket_status(
    ticket_id: str,
    new_status: str,
    worklog: Optional[str] = None,
    operator: str = "SOAR_SYSTEM"
) -> Dict[str, Any]:
    """티켓 상태 동기화 함수 래퍼"""
    return MockTicketingSystem.sync_ticket_status(ticket_id, new_status, worklog, operator)

def get_ticket(ticket_id: str) -> Optional[Dict[str, Any]]:
    return MockTicketingSystem.get_ticket(ticket_id)
