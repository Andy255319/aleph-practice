import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List

class VIPAccountException(Exception):
    """VIP 계정에 대해 승인 없이 자동 잠금을 시도할 때 발생하는 예외"""
    pass

class MissingReasonException(Exception):
    """차단 해제 시 사유가 누락되었을 때 발생하는 예외"""
    pass

def _get_base_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _get_log_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "containment_log.json")

def _get_vip_config_path() -> str:
    return os.path.join(_get_base_dir(), "config", "vip_accounts.json")

def is_vip_account(account_id: str) -> bool:
    """VIP 계정 여부 확인"""
    vip_file = _get_vip_config_path()
    if not os.path.exists(vip_file):
        return False
    try:
        with open(vip_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            vips = [v["account_id"] for v in data.get("vip_accounts", [])]
            return account_id in vips
    except Exception:
        return False

def get_vip_info(account_id: str) -> Optional[Dict[str, Any]]:
    """VIP 계정 상세 정보 반환"""
    vip_file = _get_vip_config_path()
    if not os.path.exists(vip_file):
        return None
    try:
        with open(vip_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            for v in data.get("vip_accounts", []):
                if v["account_id"] == account_id:
                    return v
    except Exception:
        return None
    return None

def log_action(
    action_type: str,
    target: str,
    status: str,
    details: str,
    operator: str = "SOAR_AUTO"
) -> Dict[str, Any]:
    """모든 조치 이력을 일관된 규격으로 기록하고 파일(containment_log.json)에 누적"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "action_type": action_type,
        "target": target,
        "status": status,
        "details": details,
        "operator": operator
    }

    log_path = _get_log_path()
    logs = []
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []

    logs.append(log_entry)

    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)

    return log_entry

def lock_account(
    account_id: str,
    reason: str,
    operator: str = "SOAR_AUTO",
    is_approved: bool = False
) -> Dict[str, Any]:
    """계정 잠금 함수 - VIP 계정인 경우 승인 없이는 잠금 불가 및 예외 발생"""
    if is_vip_account(account_id) and not is_approved:
        vip_info = get_vip_info(account_id) or {}
        role = vip_info.get("role", "VIP")
        exemption = vip_info.get("exemption_reason", "VIP 보호 정책")
        log_action(
            action_type="lock_account",
            target=account_id,
            status="BYPASS_APPROVAL_REQUIRED",
            details=f"VIP 계정({role}) 자동 잠금 거부됨: {exemption}. 사전 승인 필요",
            operator=operator
        )
        raise VIPAccountException(
            f"대상 계정 '{account_id}'은(는) VIP 계정({role})입니다. 자동 잠금이 차단되었으며 사전 승인이 필요합니다. (사유: {exemption})"
        )

    # 잠금 실행
    details = f"계정 비활성화 완료. 사유: {reason}"
    if is_approved:
        details += " [승인 게이트 통과]"
    entry = log_action("lock_account", account_id, "SUCCESS", details, operator)
    return entry

def unlock_account(
    account_id: str,
    reason: str,
    operator: str = "SOAR_ADMIN"
) -> Dict[str, Any]:
    """계정 잠금 해제 함수 - 해제 사유 필수"""
    if not reason or not reason.strip():
        raise MissingReasonException("계정 잠금 해제 시 반드시 명확한 해제 사유를 기재해야 합니다.")

    details = f"계정 정상 복구 완료. 해제 사유: {reason}"
    return log_action("unlock_account", account_id, "SUCCESS", details, operator)

def block_ip(
    ip_address: str,
    reason: str,
    operator: str = "SOAR_AUTO"
) -> Dict[str, Any]:
    """공격 IP 차단 함수 (방화벽 및 WAF 규칙 추가 모의)"""
    details = f"방화벽 인바운드 차단 규칙 적용 완료 (Drop all). 사유: {reason}"
    return log_action("block_ip", ip_address, "SUCCESS", details, operator)

def unblock_ip(
    ip_address: str,
    reason: str,
    operator: str = "SOAR_ADMIN"
) -> Dict[str, Any]:
    """IP 차단 해제 함수 - 해제 사유 필수"""
    if not reason or not reason.strip():
        raise MissingReasonException("IP 차단 해제 시 반드시 명확한 해제 사유를 기재해야 합니다.")

    details = f"방화벽 차단 규칙 롤백 완료. 해제 사유: {reason}"
    return log_action("unblock_ip", ip_address, "SUCCESS", details, operator)

def terminate_session(
    account_id: str,
    session_id: str,
    reason: str,
    operator: str = "SOAR_AUTO"
) -> Dict[str, Any]:
    """활성 세션 강제 종료 함수"""
    target = f"{account_id} (Session: {session_id})"
    details = f"세션 토큰 폐기 및 Redis 캐시 세션 무효화 완료. 사유: {reason}"
    return log_action("terminate_session", target, "SUCCESS", details, operator)

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
