import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from soar.containment import (
    lock_account,
    unlock_account,
    block_ip,
    unblock_ip,
    terminate_session,
    is_vip_account,
    VIPApprovalRequired,
    log_action
)


def _get_base_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _get_risk_levels_path() -> str:
    return os.path.join(_get_base_dir(), "config", "risk_levels.json")

def load_risk_levels() -> Dict[str, Any]:
    with open(_get_risk_levels_path(), "r", encoding="utf-8") as f:
        return json.load(f)

class ApprovalGateError(Exception):
    """승인이 필요한 작업에 대해 승인 없이 실행을 시도할 때 발생"""
    pass

class ApprovalGate:
    """조치 유형별 위험 등급(Low/High/Critical)을 판별하여 자동 실행 또는 사전 승인 분기를 수행하는 공통 게이트"""

    def __init__(self):
        self.risk_policy = load_risk_levels().get("actions", {})

    def evaluate_risk(self, action_type: str, target: str) -> Dict[str, Any]:
        policy = self.risk_policy.get(action_type, {
            "risk_level": "critical",
            "requires_approval": True,
            "description": "미분류 작업 (기본 Critical 분류)",
            "auto_executable": False
        })
        
        # VIP 계정에 대한 조치는 무조건 승인 필요 및 최고위 위험도로 상향
        is_vip = False
        if action_type in ["lock_account", "terminate_session"]:
            is_vip = is_vip_account(target)

        effective_risk = policy["risk_level"]
        requires_approval = policy["requires_approval"]

        if is_vip and action_type == "lock_account":
            effective_risk = "critical"
            requires_approval = True

        return {
            "action_type": action_type,
            "target": target,
            "risk_level": effective_risk,
            "requires_approval": requires_approval,
            "is_vip": is_vip,
            "policy": policy
        }

    def execute_action(
        self,
        action_type: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        approver: Optional[str] = None,
        operator: str = "SOAR_AUTO"
    ) -> Dict[str, Any]:
        params = params or {}
        reason = params.get("reason", "SOAR 정책에 따른 보안 대응 조치")
        eval_result = self.evaluate_risk(action_type, target)
        
        # 승인 필요 작업인데 승인자(approver)가 없는 경우 승인 대기로 분기
        if eval_result["requires_approval"] and not approver:
            log_action(
                action=action_type,
                target=target,
                result="APPROVAL_PENDING",
                reason=f"위험등급[{eval_result['risk_level'].upper()}] - 관리자 승인 대기 등록됨. (VIP 여부: {eval_result['is_vip']})"
            )
            return {
                "success": False,
                "status": "APPROVAL_PENDING",
                "risk_level": eval_result["risk_level"],
                "action_type": action_type,
                "target": target,
                "message": f"작업 '{action_type}'(위험도: {eval_result['risk_level']})는 승인이 필요합니다. 승인자 승인 후 재실행하십시오.",
                "is_vip": eval_result["is_vip"]
            }

        # 승인 게이트 통과 후 실제 조치 실행 (containment 함수들 호출)
        try:
            is_approved = bool(approver)
            exec_operator = f"APPROVED_BY({approver})" if approver else operator

            if action_type == "lock_account":
                res = lock_account(
                    username=target,
                    reason=reason,
                    is_approved=is_approved
                )
            elif action_type == "block_ip":
                res = block_ip(
                    ip_address=target,
                    reason=reason
                )
            elif action_type == "terminate_session":
                res = terminate_session(
                    username=target,
                    reason=reason
                )
            elif action_type == "unlock_account":
                res = unlock_account(
                    username=target,
                    reason=reason
                )
            elif action_type == "unblock_ip":
                res = unblock_ip(
                    ip_address=target,
                    reason=reason
                )
            else:
                raise ValueError(f"지원하지 않는 조치 유형입니다: {action_type}")

            return {
                "success": True,
                "status": "EXECUTED",
                "risk_level": eval_result["risk_level"],
                "action_type": action_type,
                "target": target,
                "approver": approver,
                "execution_result": res
            }

        except VIPApprovalRequired as ve:
            return {
                "success": False,
                "status": "VIP_BLOCKED",
                "risk_level": "critical",
                "action_type": action_type,
                "target": target,
                "error": str(ve)
            }



_gate_instance = ApprovalGate()

def execute_action(
    action_type: str,
    target: str,
    params: Optional[Dict[str, Any]] = None,
    approver: Optional[str] = None,
    operator: str = "SOAR_AUTO"
) -> Dict[str, Any]:
    """공통 승인 게이트 실행 함수"""
    return _gate_instance.execute_action(action_type, target, params, approver, operator)


def handle_false_positive(
    incident_id: str,
    target_account: str,
    target_ip: str,
    fp_reason: str,
    operator: str = "SEC_ANALYST_CHOI",
    raw_event: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    DAY 4 5단계:
    오탐 복구 함수 - 즉시 해제 + 원인 기록 + 4과목 라벨 데이터 추가 자동화
    """
    rollback_results = []

    # 1. 즉시 해제 (계정 잠금 해제 + IP 차단 해제)
    if target_account:
        try:
            res_acc = unlock_account(
                username=target_account,
                reason=f"[오탐 복구] {fp_reason}"
            )
            rollback_results.append(res_acc)
        except Exception as e:
            rollback_results.append({"error": f"계정 해제 실패: {str(e)}"})

    if target_ip:
        try:
            res_ip = unblock_ip(
                ip_address=target_ip,
                reason=f"[오탐 복구] {fp_reason}"
            )
            rollback_results.append(res_ip)
        except Exception as e:
            rollback_results.append({"error": f"IP 차단 해제 실패: {str(e)}"})


    # 2. 4과목 AI/ML 탐지 모델 재학습용 라벨 데이터 추가
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "false_positive_dataset.json")
    dataset = []
    if os.path.exists(dataset_path):
        try:
            with open(dataset_path, "r", encoding="utf-8") as f:
                dataset = json.load(f)
        except Exception:
            dataset = []

    label_entry = {
        "event_id": incident_id,
        "timestamp": datetime.now().isoformat(),
        "ground_truth_label": "FALSE_POSITIVE",
        "verified_by": operator,
        "reason": fp_reason,
        "features": {
            "source_ip": target_ip,
            "target_account": target_account,
            "raw_event_summary": raw_event or {}
        },
        "ml_feedback": "해당 패턴은 정상 행위로 피드백 가중치 조정 필요 (Retrain Target)"
    }
    dataset.append(label_entry)

    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    return {
        "incident_id": incident_id,
        "status": "FALSE_POSITIVE_RESOLVED",
        "rollback_actions": rollback_results,
        "labeled_data_recorded": label_entry
    }
