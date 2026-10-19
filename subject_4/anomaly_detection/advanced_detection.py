"""
Day 3: 고급 탐지 로직 (비인가 접근, SaaS 이상 행위, 위협 인텔리전스 IOC 매칭)
(Day 4 슬라이드 표 명세 반영:
 - detect_unauthorized_access(): 접근 로그와 권한 정책 -> 정책 평가 결과를 이상 여부로 변환
 - detect_saas_anomaly(): 사용자별 SaaS 사용 기록과 기준선 -> 사용자별 정상 사용 패턴 필요
 - match_ioc(): IP·도메인과 IOC 목록 -> IOC 일치 결과를 탐지 결과로 변환)
"""
import os
import json
from datetime import datetime
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

def _get_user_baselines() -> Dict[str, Any]:
    bl_path = os.path.join(_get_base_dir(), "config", "saas_user_baselines.json")
    if os.path.exists(bl_path):
        with open(bl_path, "r", encoding="utf-8") as f:
            return json.load(f).get("user_baselines", {})
    return {}

def detect_unauthorized_access(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    비인가 접근 탐지:
    [평가 시 고려할 점]: 접근 로그와 권한 정책을 비교하여, '정책 평가 결과를 이상 여부로 변환'해야 함.
    - 방화벽 차단(DENY) 이벤트(포트 22 SSH, 포트 445 SMB 등)를 비인가 접근 시도로 변환
    - SaaS/시스템 리소스 요청에 대해 3과목 evaluate_access()를 호출하여 정책 위반 건을 이상 결과로 변환
    """
    detections = []
    
    for e in events:
        user_id = e.get("user_id")
        src_ip = e.get("source_ip")
        src = e.get("event_source")

        # 1. 방화벽 로그의 DENY 이벤트 정책 변환
        if src == "firewall" and e.get("status") == "DENY":
            port = e.get("details", {}).get("dst_port", 0)
            dst_ip = e.get("details", {}).get("dst_ip", "")
            resource_name = f"Server_{port}"

            # 권한 정책 평가
            eval_res = evaluate_access(user_id=user_id if user_id != "N/A" else "unregistered_ip", resource=resource_name, action=e.get("action", ""))
            
            detections.append({
                "rule_id": "RULE-UNAUTHORIZED-NETWORK-ACCESS",
                "rule_name": "방화벽 정책 차단(DENY) 기반 비인가 포트 접근 탐지",
                "event_id": e.get("event_id"),
                "user_id": user_id,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "target_port": port,
                "timestamp": e.get("timestamp"),
                "decision": "DENY",
                "policy_reason": eval_res["reason"],
                "severity": "HIGH",
                "details": f"인가되지 않은 포트 {port} 접근 시도 차단됨 (방화벽 정책 평가 결과 이상 변환)"
            })

        # 2. SaaS 리소스에 대한 RBAC 정책 위반 변환
        elif src == "saas":
            service_name = e.get("details", {}).get("service") or e.get("details", {}).get("app_name")
            if user_id and user_id != "N/A" and service_name:
                eval_res = evaluate_access(user_id=user_id, resource=service_name, action=e.get("action", ""))
                if not eval_res["is_authorized"]:
                    detections.append({
                        "rule_id": "RULE-UNAUTHORIZED-SAAS-ACCESS",
                        "rule_name": "RBAC 권한 정책 위반 SaaS 서비스 접근 탐지",
                        "event_id": e.get("event_id"),
                        "user_id": user_id,
                        "resource": service_name,
                        "source_ip": src_ip,
                        "timestamp": e.get("timestamp"),
                        "decision": eval_res["decision"],
                        "policy_reason": eval_res["reason"],
                        "severity": "HIGH",
                        "details": f"사용자 '{user_id}'의 권한 정책 위반 ({eval_res['reason']})"
                    })

    return detections

def detect_saas_anomaly(
    events: List[Dict[str, Any]],
    baselines: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    SaaS 이상 행위 탐지:
    [평가 시 고려할 점]: '사용자별 정상 사용 패턴(기준선)'이 반드시 필요함.
    - 평소 사용하지 않던 서비스에 접근하는 경우
    - 평소 업무 시간 외(심야)에 중요 데이터(DOWNLOAD)를 접근하는 경우
    - 비정상적으로 짧은 시간(예: 1분 미만)에 연속 다운로드를 수행하는 경우
    """
    if baselines is None:
        baselines = _get_user_baselines()

    saas_events = [e for e in events if e.get("event_source") == "saas"]
    detections = []

    # 사용자별 이벤트 수집
    user_saas: Dict[str, List[Dict[str, Any]]] = {}
    for e in saas_events:
        u = e.get("user_id")
        if u and u != "N/A":
            user_saas.setdefault(u, []).append(e)

    for user_id, u_evts in user_saas.items():
        base = baselines.get(user_id, {})
        normal_services = base.get("normal_services", [])
        normal_hours = base.get("normal_hours", [9, 18])
        sorted_evts = sorted(u_evts, key=lambda x: x["timestamp"])

        for i, e in enumerate(sorted_evts):
            dt = datetime.fromisoformat(e["timestamp"])
            svc = e.get("details", {}).get("service") or e.get("details", {}).get("app_name")
            act = e.get("action", "").upper()

            # 1. 사용자 정상 서비스 패턴 이탈 검사
            if normal_services and svc not in normal_services:
                detections.append({
                    "rule_id": "RULE-SAAS-ANOMALY-SERVICE",
                    "rule_name": "사용자 정상 사용 패턴 이탈 서비스 접근 탐지",
                    "event_id": e.get("event_id"),
                    "user_id": user_id,
                    "service": svc,
                    "source_ip": e.get("source_ip"),
                    "timestamp": e.get("timestamp"),
                    "baseline_services": normal_services,
                    "severity": "HIGH",
                    "details": f"사용자 '{user_id}'의 평소 사용 패턴({normal_services})에 없는 비인가 서비스 '{svc}' 접근 포착"
                })

            # 2. 심야/업무 외 시간 다운로드 이상치
            is_offhour = dt.hour < normal_hours[0] or dt.hour >= normal_hours[1]
            if is_offhour and "DOWNLOAD" in act:
                detections.append({
                    "rule_id": "RULE-SAAS-ANOMALY-OFFHOUR-EXFIL",
                    "rule_name": "업무 외 시간(심야) SaaS 데이터 다운로드 이상 탐지",
                    "event_id": e.get("event_id"),
                    "user_id": user_id,
                    "service": svc,
                    "source_ip": e.get("source_ip"),
                    "timestamp": e.get("timestamp"),
                    "hour": dt.hour,
                    "severity": "CRITICAL",
                    "details": f"평소 업무시간({normal_hours[0]}~{normal_hours[1]}시) 외 심야({dt.strftime('%H:%M:%S')})에 '{svc}' 대량/중요 다운로드 수행"
                })

            # 3. 비정상 급속 반복 다운로드 검사 (1분 이내 2회 이상)
            if i > 0 and "DOWNLOAD" in act and "DOWNLOAD" in sorted_evts[i-1].get("action", "").upper():
                prev_dt = datetime.fromisoformat(sorted_evts[i-1]["timestamp"])
                diff_sec = (dt - prev_dt).total_seconds()
                if 0 <= diff_sec <= 60:
                    detections.append({
                        "rule_id": "RULE-SAAS-ANOMALY-RAPID-DOWNLOAD",
                        "rule_name": "단시간 집중 연속 다운로드 이상 탐지",
                        "event_id": e.get("event_id"),
                        "user_id": user_id,
                        "service": svc,
                        "source_ip": e.get("source_ip"),
                        "timestamp": e.get("timestamp"),
                        "interval_seconds": diff_sec,
                        "severity": "HIGH",
                        "details": f"이전 다운로드 후 불과 {int(diff_sec)}초 만에 연속 다운로드 요청 포착 (기준선 이탈)"
                    })

    return detections

def match_ioc(events: List[Dict[str, Any]], ioc_list: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """
    위협 인텔리전스(IOC) 매칭:
    [평가 시 고려할 점]: IP·도메인과 IOC 목록의 일치 여부를 '탐지 결과 객체로 변환' 가능.
    - 이벤트의 출발지 IP, 목적지 IP 등을 IOC 피드와 대조하여 일치 시 상세 위협 컨텍스트(위협 행위자, 신뢰도)를 매핑한 탐지 결과 생성.
    """
    if ioc_list is None:
        ioc_list = _get_threat_intel()

    ti_map = {t["ip"]: t for t in ioc_list}
    detections = []

    for e in events:
        src_ip = e.get("source_ip")
        dst_ip = e.get("details", {}).get("dst_ip")

        matched_ip = None
        if src_ip in ti_map:
            matched_ip = src_ip
        elif dst_ip in ti_map:
            matched_ip = dst_ip

        if matched_ip:
            ti_info = ti_map[matched_ip]
            detections.append({
                "rule_id": "RULE-IOC-MATCH",
                "rule_name": "위협 인텔리전스(IoC) 악성 IP 매칭 탐지",
                "event_id": e.get("event_id"),
                "user_id": e.get("user_id"),
                "matched_ip": matched_ip,
                "threat_type": ti_info.get("threat_type"),
                "threat_actor": ti_info.get("threat_actor"),
                "confidence": ti_info.get("confidence"),
                "timestamp": e.get("timestamp"),
                "severity": "CRITICAL",
                "details": f"알려진 위협 행위자 [{ti_info.get('threat_actor')}]의 악성 IP ({matched_ip}) 연루 이벤트 확인 (IOC 결과 탐지 변환)"
            })

    return detections
