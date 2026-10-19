"""
Day 3: 고급 탐지 로직 (비인가 접근, SaaS 이상 행위, 위협 인텔리전스 IOC 매칭)
"""
import os
import json
from typing import List, Dict, Any, Optional
from access_control.policy import evaluate_access

def _get_base_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _get_threat_intel() -> List[Dict[str, Any]]:
    ti_path = os.path.join(_get_base_dir(), "config", "threat_intel.json")
    if os.path.exists(ti_path):
        with open(ti_path, "r", encoding="utf-8") as f:
            return json.load(f).get("malicious_ips", [])
    return []

def _get_thresholds() -> Dict[str, Any]:
    cfg_path = os.path.join(_get_base_dir(), "config", "detection_thresholds.json")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f).get("saas_detection", {})
    return {"mass_download_file_threshold": 50, "export_record_threshold": 300}

def detect_unauthorized_access(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    3과목 access_control/policy.py의 evaluate_access()를 연동하여
    정책 및 예외 승인 여부를 반영한 비인가 접근 탐지
    """
    detections = []
    for e in events:
        user_id = e.get("user_id")
        if not user_id or user_id == "N/A":
            continue

        resource = None
        action = e.get("action", "")

        # SaaS 이벤트의 경우 대상 리소스 매핑
        if e.get("event_source") == "saas":
            resource = e.get("details", {}).get("app_name")
        elif "connect_" in action:
            resource = f"Server_{e.get('details', {}).get('port', 0)}"

        if not resource:
            continue

        eval_res = evaluate_access(user_id=user_id, resource=resource, action=action)
        if not eval_res["is_authorized"]:
            detections.append({
                "rule_id": "RULE-UNAUTHORIZED-ACCESS",
                "rule_name": "접근통제 정책 위반 비인가 리소스 접근 탐지",
                "event_id": e.get("event_id"),
                "user_id": user_id,
                "resource": resource,
                "source_ip": e.get("source_ip"),
                "timestamp": e.get("timestamp"),
                "decision": eval_res["decision"],
                "reason": eval_res["reason"],
                "exception_applied": eval_res.get("exception_applied", False),
                "severity": "HIGH",
                "details": f"RBAC 정책 거부: {eval_res['reason']}"
            })

    return detections

def detect_saas_anomaly(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    SaaS 이상 행위 탐지:
    - 단일 작업 대량 파일 다운로드 (임계값 이상)
    - 대량 데이터 내보내기 (export)
    - 관리자 권한 상승 시도
    """
    cfg = _get_thresholds()
    download_thresh = cfg.get("mass_download_file_threshold", 50)
    saas_events = [e for e in events if e.get("event_source") == "saas"]
    detections = []

    for e in saas_events:
        action = e.get("action", "")
        details = e.get("details", {})
        file_cnt = details.get("file_count", 0)

        # 1. 대량 다운로드 탐지
        if "download" in action and file_cnt >= download_thresh:
            detections.append({
                "rule_id": "RULE-SAAS-MASS-DOWNLOAD",
                "rule_name": "SaaS 대량 파일 다운로드(데이터 유출 의심) 탐지",
                "event_id": e.get("event_id"),
                "user_id": e.get("user_id"),
                "app_name": details.get("app_name"),
                "file_count": file_cnt,
                "timestamp": e.get("timestamp"),
                "severity": "CRITICAL",
                "details": f"임계치({download_thresh}개)를 초과하는 {file_cnt}개 파일 일괄 다운로드 포착"
            })

        # 2. 대량 데이터 보고서 내보내기 (export_report)
        if "export" in action and file_cnt >= 200:
            detections.append({
                "rule_id": "RULE-SAAS-DATA-EXPORT",
                "rule_name": "SaaS 대량 고객/보고서 데이터 추출 탐지",
                "event_id": e.get("event_id"),
                "user_id": e.get("user_id"),
                "app_name": details.get("app_name"),
                "file_count": file_cnt,
                "timestamp": e.get("timestamp"),
                "severity": "HIGH",
                "details": f"SaaS 상에서 {file_cnt}건의 대량 데이터 외부 반출(Export) 포착"
            })

        # 3. 비인가 권한 상승 거부
        if "escalation" in action and e.get("status") == "DENIED":
            detections.append({
                "rule_id": "RULE-SAAS-PRIV-ESCALATION",
                "rule_name": "SaaS 관리자 권한 무단 상승 거부 탐지",
                "event_id": e.get("event_id"),
                "user_id": e.get("user_id"),
                "app_name": details.get("app_name"),
                "timestamp": e.get("timestamp"),
                "severity": "HIGH",
                "details": f"관리자 권한 강제 획득 시도 차단됨"
            })

    return detections

def match_ioc(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    config/threat_intel.json의 위협 인텔리전스 IP와 로그 이벤트의 IP를 매칭
    """
    ti_list = _get_threat_intel()
    ti_map = {t["ip"]: t for t in ti_list}

    detections = []
    for e in events:
        src_ip = e.get("source_ip")
        if src_ip in ti_map:
            ti_info = ti_map[src_ip]
            detections.append({
                "rule_id": "RULE-IOC-MATCH",
                "rule_name": "알려진 위협 인텔리전스(IoC) 악성 IP 통신 탐지",
                "event_id": e.get("event_id"),
                "user_id": e.get("user_id"),
                "matched_ip": src_ip,
                "threat_type": ti_info.get("threat_type"),
                "threat_actor": ti_info.get("threat_actor"),
                "confidence": ti_info.get("confidence"),
                "timestamp": e.get("timestamp"),
                "severity": "CRITICAL",
                "details": f"위협 행위자 [{ti_info.get('threat_actor')}]의 C2/악성 IP ({src_ip})와의 통신 확인"
            })

    return detections
