"""
Day 2: 계정잠금·접근차단 자동화 스크립트 모듈
"""
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional, List

class VIPApprovalRequired(Exception):
    """VIP 계정 잠금 요청 시 발생하는 예외 (사전 승인 필수)"""
    pass

# 테스트 모드 상태 저장소 (가상 인메모리 시스템 상태)
_ACTIVE_LOCKED_ACCOUNTS = set()
_ACTIVE_BLOCKED_IPS = set()
_ACTIVE_SESSIONS = {"lee": "sess_token_lee_01", "kim": "sess_token_kim_01"}

def _get_base_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _get_log_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "containment_log.json")

def _get_vip_config_path() -> str:
    return os.path.join(_get_base_dir(), "config", "vip_accounts.json")

def is_vip_account(username: str) -> bool:
    """VIP 계정 목록 확인"""
    cfg_path = _get_vip_config_path()
    if not os.path.exists(cfg_path):
        return False
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            vips = data.get("vip_accounts", [])
            return username in vips
    except Exception:
        return False

def log_action(
    action: str = "",
    target: str = "",
    result: str = "",
    reason: str = "",
    **kwargs
) -> Dict[str, Any]:
    """
    모든 조치 함수 호출 시 성공·실패·건너뜀·승인 필요 결과를 JSON 파일에 누적 기록
    - 시간(timestamp), 조치 유형(action), 대상(target), 결과(result), 사유(reason)
    - action_type, status, details, operator 등 키워드 인자 호환 지원
    """
    act = action or kwargs.get("action_type", "")
    tgt = target
    res = result or kwargs.get("status", "")
    rsn = reason or kwargs.get("details", "")

    entry = {
        "timestamp": datetime.now().isoformat(),
        "action": act,
        "target": tgt,
        "result": res,
        "reason": rsn
    }
    if "operator" in kwargs:
        entry["operator"] = kwargs["operator"]

    log_path = _get_log_path()
    logs = []
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []

    logs.append(entry)

    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)

    return entry

def lock_account(username: str, reason: str, is_approved: bool = False) -> Dict[str, Any]:
    """
    일반 계정 잠금.
    VIP 계정인 경우:
      1. 승인 필요 결과를 log_action()에 기록
      2. VIPApprovalRequired 예외를 발생시킨다. (단, is_approved=True이면 승인 통과로 잠금 수행)
    """
    if is_vip_account(username) and not is_approved:
        # 1. 승인 필요 결과 기록
        log_action(
            action="lock_account",
            target=username,
            result="APPROVAL_REQUIRED",
            reason=f"[VIP 보호] 계정 잠금 사전 승인 필요: {reason}"
        )
        # 2. VIPApprovalRequired 예외 발생
        raise VIPApprovalRequired(f"VIP 계정 '{username}'에 대한 잠금 요청은 사전 승인이 필요합니다.")

    # 일반 계정 잠금 처리
    _ACTIVE_LOCKED_ACCOUNTS.add(username)
    entry = log_action(
        action="lock_account",
        target=username,
        result="SUCCESS",
        reason=reason + (" [사전 승인 완료]" if is_approved else "")
    )
    return entry


def unlock_account(username: str, reason: str) -> Dict[str, Any]:
    """
    계정 잠금 해제.
    - 사유가 없거나 공백만 입력된 경우 실행하지 않는다 (실패 기록).
    - 존재하지 않는 대상 / 이미 해제된 대상 처리 (건너뜀 기록).
    """
    # 1. 사유 누락 검사
    if not reason or not reason.strip():
        return log_action(
            action="unlock_account",
            target=username,
            result="FAIL",
            reason="해제 사유 누락 (사유가 없거나 공백)"
        )

    # 2. 이미 해제되었거나 잠금 대상이 아닌 경우
    if username not in _ACTIVE_LOCKED_ACCOUNTS:
        return log_action(
            action="unlock_account",
            target=username,
            result="SKIPPED",
            reason="이미 잠금 해제되었거나 잠금 상태가 아닌 계정"
        )

    # 정상 해제
    _ACTIVE_LOCKED_ACCOUNTS.remove(username)
    return log_action(
        action="unlock_account",
        target=username,
        result="SUCCESS",
        reason=reason
    )

def block_ip(ip_address: str, reason: str) -> Dict[str, Any]:
    """IP 차단 처리 (테스트 모드에서는 실제 방화벽 대신 가상 차단 기록)"""
    _ACTIVE_BLOCKED_IPS.add(ip_address)
    return log_action(
        action="block_ip",
        target=ip_address,
        result="SUCCESS",
        reason=reason
    )

def unblock_ip(ip_address: str, reason: str) -> Dict[str, Any]:
    """
    IP 차단 해제.
    - 사유가 없거나 공백만 입력된 경우 실행하지 않는다.
    - 존재하지 않는 대상 / 이미 해제된 대상 처리.
    """
    # 1. 사유 누락 검사
    if not reason or not reason.strip():
        return log_action(
            action="unblock_ip",
            target=ip_address,
            result="FAIL",
            reason="해제 사유 누락 (사유가 없거나 공백)"
        )

    # 2. 이미 차단 해제된 대상
    if ip_address not in _ACTIVE_BLOCKED_IPS:
        return log_action(
            action="unblock_ip",
            target=ip_address,
            result="SKIPPED",
            reason="이미 차단 해제되었거나 차단 목록에 없는 IP"
        )

    _ACTIVE_BLOCKED_IPS.remove(ip_address)
    return log_action(
        action="unblock_ip",
        target=ip_address,
        result="SUCCESS",
        reason=reason
    )

def terminate_session(username: str, reason: str) -> Dict[str, Any]:
    """해당 사용자의 활성 세션을 무효화한다."""
    if username in _ACTIVE_SESSIONS:
        del _ACTIVE_SESSIONS[username]

    return log_action(
        action="terminate_session",
        target=username,
        result="SUCCESS",
        reason=reason
    )

def get_all_containment_logs() -> List[Dict[str, Any]]:
    """모든 조치 이력 조회"""
    log_path = _get_log_path()
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []
