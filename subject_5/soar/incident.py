import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List

VALID_STATUSES = [
    "NEW",
    "ANALYZING",
    "APPROVAL_PENDING",
    "CONTAINMENT",
    "REMEDIATION",
    "CLOSED",
    "FALSE_POSITIVE"
]

class Incident:
    def __init__(
        self,
        incident_id: str,
        event_type: str,
        severity: str,
        source_ip: str,
        target_account: str,
        description: str,
        raw_log: Optional[Dict[str, Any]] = None
    ):
        self.incident_id = incident_id
        self.event_type = event_type
        self.severity = severity
        self.source_ip = source_ip
        self.target_account = target_account
        self.description = description
        self.raw_log = raw_log or {}
        self.status = "NEW"
        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        self.matched_playbook: Optional[Dict[str, Any]] = None
        self.history: List[Dict[str, Any]] = [
            {
                "timestamp": self.created_at,
                "status": "NEW",
                "comment": "인시던트 등록 완료",
                "operator": "SYSTEM"
            }
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "target_account": self.target_account,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "matched_playbook": self.matched_playbook,
            "raw_log": self.raw_log,
            "history": self.history
        }


def update_status(incident: Incident, new_status: str, comment: str = "", operator: str = "SYSTEM") -> Incident:
    """인시던트 상태 전이 및 히스토리 업데이트 함수"""
    if new_status not in VALID_STATUSES:
        raise ValueError(f"유효하지 않은 상태 전이입니다: {new_status}. 허용 상태: {VALID_STATUSES}")

    now_ts = datetime.now().isoformat()
    old_status = incident.status
    incident.status = new_status
    incident.updated_at = now_ts
    incident.history.append({
        "timestamp": now_ts,
        "from_status": old_status,
        "status": new_status,
        "comment": comment,
        "operator": operator
    })
    return incident


def match_playbook(event_type: str, config_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """이벤트 유형에 대응되는 플레이북을 config/playbook_registry.json에서 매칭"""
    if config_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "config", "playbook_registry.json")

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"플레이북 설정 파일을 찾을 수 없습니다: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        registry = json.load(f)

    for pb in registry.get("playbooks", []):
        if pb.get("event_type") == event_type:
            return pb

    return None
