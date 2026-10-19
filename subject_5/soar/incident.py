"""
Day 1: Incident 상태 관리 및 플레이북 자동 매칭 모듈
"""
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional, List

def _get_base_dir() -> str:
    # subject_5 루트 디렉토리 탐색
    curr = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(curr) in ["soar", "soar_response"]:
        return os.path.dirname(curr)
    return curr

def _get_registry_path() -> str:
    return os.path.join(_get_base_dir(), "config", "playbook_registry.json")

def create_incident(
    event_id: str = "evt-2001",
    status: str = "detected",
    message: str = "비정상 로그인 탐지",
    **kwargs
) -> Dict[str, Any]:
    """
    슬라이드 규격 인시던트 생성:
    incident = {
        "event_id": "evt-2001",
        "status": "triaged",
        "history": [
            {"status": "detected", "message": "비정상 로그인 탐지"},
            ...
        ]
    }
    """
    inc = {
        "event_id": event_id,
        "incident_id": event_id,  # 호환용
        "status": status,
        "history": [
            {
                "status": status,
                "message": message,
                "timestamp": datetime.now().isoformat()
            }
        ]
    }
    # 추가 속성 병합 (target_account, source_ip, event_type, severity 등)
    inc.update(kwargs)
    return inc

def update_status(
    incident: Any,
    new_status: str,
    message: str = "",
    comment: Optional[str] = None,
    operator: str = "SYSTEM"
) -> Any:
    """
    update_status() 함수는 다음 기능을 수행하도록 구현한다:
    1. incident의 현재 status를 변경한다.
    2. 변경된 상태와 처리 내용을 history에 추가한다.
    3. 처리 이력을 출력해 상태 변경이 정상적으로 이루어졌는지 확인한다.
    """
    msg = message or comment or f"상태가 {new_status}로 변경되었습니다."

    # Dict 형태 인시던트 처리
    if isinstance(incident, dict):
        old_status = incident.get("status", "UNKNOWN")
        incident["status"] = new_status
        history_entry = {
            "status": new_status,
            "message": msg,
            "timestamp": datetime.now().isoformat()
        }
        incident.setdefault("history", []).append(history_entry)
        
        # 처리 이력 출력하여 상태 변경 확인
        print(f"[상태 전이 확인] Event ID: {incident.get('event_id')} | 상태: {old_status} -> {new_status} | 내용: {msg}")
        return incident

    # 클래스 객체 형태 인시던트 호환 처리
    if hasattr(incident, "status") and hasattr(incident, "history"):
        old_status = incident.status
        incident.status = new_status
        incident.updated_at = datetime.now().isoformat()
        entry = {
            "status": new_status,
            "message": msg,
            "comment": msg,
            "operator": operator,
            "timestamp": datetime.now().isoformat()
        }
        incident.history.append(entry)
        print(f"[상태 전이 확인] Incident ID: {getattr(incident, 'incident_id', 'N/A')} | 상태: {old_status} -> {new_status} | 내용: {msg}")
        return incident

    return incident

def match_playbook(
    event_type: str,
    config_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    플레이북 레지스트리(config/playbook_registry.json)에서
    이벤트 유형(event_type)에 대응하는 플레이북을 매칭한다.
    """
    path = config_path or _get_registry_path()
    if not os.path.exists(path):
        raise FileNotFoundError(f"플레이북 레지스트리 파일을 찾을 수 없습니다: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 대소문자 및 표준 포맷 정규화 매칭
    clean_type = event_type.strip().upper()
    type_aliases = {
        "ABNORMAL_LOGIN": "ABNORMAL_LOGIN",
        "LOGIN": "ABNORMAL_LOGIN",
        "TRAFFIC_SPIKE": "TRAFFIC_SPIKE",
        "TRAFFIC": "TRAFFIC_SPIKE",
        "CORRELATION_ATTACK": "CORRELATED_ATTACK",
        "CORRELATED_ATTACK": "CORRELATED_ATTACK",
        "CORRELATION": "CORRELATED_ATTACK"
    }
    target_type = type_aliases.get(clean_type, clean_type)

    for pb in data.get("playbooks", []):
        pb_type = pb.get("event_type", "").strip().upper()
        if pb_type == target_type or pb.get("id", "").strip().upper() == clean_type:
            return pb

    return None

class Incident:
    """하위 호환성을 위한 Incident 클래스 래퍼"""
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
        self.event_id = incident_id
        self.event_type = event_type
        self.severity = severity
        self.source_ip = source_ip
        self.target_account = target_account
        self.description = description
        self.raw_log = raw_log or {}
        self.status = "detected"
        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        self.matched_playbook: Optional[Dict[str, Any]] = None
        self.history = [
            {
                "status": "detected",
                "message": description,
                "timestamp": self.created_at
            }
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "incident_id": self.incident_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "target_account": self.target_account,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at,
            "matched_playbook": self.matched_playbook,
            "history": self.history
        }
