"""
3과목 Access Control Policy Module
RBAC 및 예외 승인 기반 접근 통제 평가 엔진 (Day 1 practice 및 Day 3 연동)
"""
from typing import Dict, Any, Optional

# 부서/역할별 인가 리소스 및 허용 서비스 정책
POLICY_RULES = {
    # 4과목 교재 실습 사용자 (kim, lee, park, choi)
    "kim": {"role": "marketing", "allowed_resources": ["drive"], "allowed_ports": [443, 80]},
    "lee": {"role": "developer", "allowed_resources": ["slack", "jira"], "allowed_ports": [443]},
    "park": {"role": "design", "allowed_resources": ["drive"], "allowed_ports": [53, 443]},
    "choi": {"role": "operations", "allowed_resources": ["mail"], "allowed_ports": [53]},
    # 기존 가상 사용자 호환
    "user_alice": {"role": "marketing", "allowed_resources": ["GoogleDrive", "Slack", "drive", "slack"], "allowed_ports": [443]},
    "user_bob": {"role": "sales", "allowed_resources": ["Salesforce", "Slack"], "allowed_ports": [443]},
    "user_charlie": {"role": "developer", "allowed_resources": ["GitHub", "Jira", "Confluence"], "allowed_ports": [443, 22]},
    "user_david": {"role": "developer", "allowed_resources": ["GitHub", "Jira"], "allowed_ports": [443]},
    "user_frank": {"role": "developer", "allowed_resources": ["GitHub", "Jira"], "allowed_ports": [443]},
    "admin_user": {"role": "admin", "allowed_resources": ["*"], "allowed_ports": ["*"]}
}

# 사전 등록된 임시 예외 승인 목록 (오탐 튜닝용)
APPROVED_EXCEPTIONS = [
    {"user_id": "user_charlie", "resource": "Salesforce", "reason": "영업 데이터 기술 지원 승인됨"},
    {"user_id": "user_alice", "resource": "Confluence", "reason": "마케팅 위키 작성 승인됨"},
    {"user_id": "choi", "resource": "Server_445", "reason": "야간 파일서버 점검 사전 승인"},
    {"user_id": "choi", "resource": "login_offhour", "reason": "야간 시스템 긴급 패치 승인"}
]

def evaluate_access(
    user_id: str,
    resource: str,
    action: str = "read",
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    접근 요청에 대해 기본 정책 및 예외 승인 여부를 평가:
    - 정책 위반 시 is_authorized = False
    - 예외 승인 내역이 있으면 is_authorized = True (exception_applied = True)
    """
    context = context or {}
    user_policy = POLICY_RULES.get(user_id)

    # 1. 예외 승인 여부 우선 확인
    for exc in APPROVED_EXCEPTIONS:
        if exc["user_id"] == user_id and exc["resource"] == resource:
            return {
                "is_authorized": True,
                "decision": "ALLOW",
                "exception_applied": True,
                "reason": f"예외 승인 정책 적용: {exc['reason']}"
            }

    # 2. 사용자 미등록 시 비인가
    if not user_policy:
        return {
            "is_authorized": False,
            "decision": "DENY",
            "exception_applied": False,
            "reason": f"미등록 사용자 '{user_id}' 접근 차단"
        }

    # 3. 허용 리소스 검사
    allowed_resources = user_policy.get("allowed_resources", [])
    allowed_ports = user_policy.get("allowed_ports", [])

    # 포트 리소스 체크 (예: Server_22, Port_22)
    if resource.startswith("Server_") or resource.startswith("Port_"):
        try:
            port_num = int(resource.split("_")[1])
            if "*" in allowed_ports or port_num in allowed_ports:
                return {
                    "is_authorized": True,
                    "decision": "ALLOW",
                    "exception_applied": False,
                    "reason": f"포트 {port_num} 인가됨"
                }
            else:
                return {
                    "is_authorized": False,
                    "decision": "DENY",
                    "exception_applied": False,
                    "reason": f"포트 {port_num}는 사용자 '{user_id}'의 인가 포트({allowed_ports})에 포함되지 않음"
                }
        except ValueError:
            pass

    if "*" in allowed_resources or resource in allowed_resources:
        return {
            "is_authorized": True,
            "decision": "ALLOW",
            "exception_applied": False,
            "reason": f"역할({user_policy.get('role')}) 기본 접근 권한 인가됨"
        }

    return {
        "is_authorized": False,
        "decision": "DENY",
        "exception_applied": False,
        "reason": f"사용자 '{user_id}'는 리소스 '{resource}'에 대한 인가 권한이 없습니다."
    }
