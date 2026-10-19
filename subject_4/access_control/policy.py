"""
3과목 Access Control Policy Module
RBAC 및 예외 승인 기반 접근 통제 평가 엔진
"""
from typing import Dict, Any, Optional

# 부서/역할별 인가 리소스 정책
POLICY_RULES = {
    "user_alice": {"role": "marketing", "allowed_resources": ["GoogleDrive", "Slack"]},
    "user_bob": {"role": "sales", "allowed_resources": ["Salesforce", "Slack"]},
    "user_charlie": {"role": "developer", "allowed_resources": ["GitHub", "Jira", "Confluence"]},
    "user_david": {"role": "developer", "allowed_resources": ["GitHub", "Jira"]},
    "user_frank": {"role": "developer", "allowed_resources": ["GitHub", "Jira"]},
    "admin_user": {"role": "admin", "allowed_resources": ["*"]}
}

# 사전 등록된 임시 예외 승인 목록
APPROVED_EXCEPTIONS = [
    {"user_id": "user_charlie", "resource": "Salesforce", "reason": "영업 데이터 기술 지원 승인됨"},
    {"user_id": "user_alice", "resource": "Confluence", "reason": "마케팅 위키 작성 승인됨"}
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
    allowed = user_policy.get("allowed_resources", [])
    if "*" in allowed or resource in allowed:
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
