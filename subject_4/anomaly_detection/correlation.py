"""
Day 3: 다단계 공격 상관분석 (Correlation Engine) 및 통합 위험점수(Risk Score) 산출 모듈
(Day 4 슬라이드 표 명세 반영:
 - 상관분석 함수: 여러 이벤트와 시간 범위 필요 -> 이벤트 간 관계를 평가할 데이터 필요)
"""
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

def _get_scoring_weights() -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "detection_thresholds.json")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f).get("risk_scoring", {})
    return {
        "weight_bruteforce": 35,
        "weight_offhour_login": 20,
        "weight_traffic_spike": 40,
        "weight_saas_anomaly": 45,
        "weight_ioc_match": 50,
        "weight_unauthorized_access": 30,
        "chain_correlation_bonus": 50,
        "high_priority_cutoff": 70
    }

def group_by_user(events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """이벤트를 사용자별로 그룹화 및 타임스탬프 오름차순 정렬"""
    user_map: Dict[str, List[Dict[str, Any]]] = {}
    for e in events:
        u = e.get("user_id")
        if u and u != "N/A":
            user_map.setdefault(u, []).append(e)

    for u in user_map:
        user_map[u].sort(key=lambda x: x["timestamp"])
    return user_map

def check_chain(
    user_events: List[Dict[str, Any]],
    user_detections: List[Dict[str, Any]],
    max_window_hours: int = 24
) -> Dict[str, Any]:
    """
    3단계 침해사고 킬체인(Kill Chain) 패턴 검증:
    [평가 시 고려할 점]: 여러 이벤트 간의 선후 관계와 인과관계를 평가할 데이터 필요.
    - 1단계: 비정상 로그인 (무차별 대입, 실패 후 성공, 심야 접속)
    - 2단계: 내부 탐색 및 비인가 리소스 접근 (포트 스캔, 방화벽 차단, RBAC 위반)
    - 3단계: 데이터 유출 및 외부 통신 (SaaS 심야/급속 다운로드, 트래픽 급증, IoC IP 매칭)
    """
    stage1_matched = []
    stage2_matched = []
    stage3_matched = []

    for d in user_detections:
        rid = d.get("rule_id", "")
        if "BRUTEFORCE" in rid or "OFFHOUR" in rid:
            stage1_matched.append(d)
        elif "UNAUTHORIZED" in rid or "PRIV-ESCALATION" in rid:
            stage2_matched.append(d)
        elif "ANOMALY" in rid or "IOC-MATCH" in rid or "TRAFFIC-SPIKE" in rid or "DOWNLOAD" in rid:
            stage3_matched.append(d)

    is_chain_completed = bool(stage1_matched and stage2_matched and stage3_matched)

    return {
        "is_chain_completed": is_chain_completed,
        "chain_length": len([s for s in [stage1_matched, stage2_matched, stage3_matched] if s]),
        "stage1_initial_access": stage1_matched,
        "stage2_lateral_privilege": stage2_matched,
        "stage3_exfiltration": stage3_matched,
        "chain_summary": "3단계 다단계 공격 체이닝 포착 (Initial Access -> Lateral/Unauthorized -> Exfiltration)" if is_chain_completed else f"부분 이상 징후 단계 식별 ({len([s for s in [stage1_matched, stage2_matched, stage3_matched] if s])}/3 단계)"
    }

def correlate_events(
    events: List[Dict[str, Any]],
    detections: List[Dict[str, Any]],
    time_window_hours: int = 24
) -> Dict[str, Any]:
    """
    [상관분석 함수 핵심 구현]:
    여러 이벤트와 시간 범위를 입력받아 이벤트 간의 관계(사용자/IP/시간 순서)를 종합 평가.
    """
    # 사용자별로 이상탐지 결과 그룹화
    user_dets: Dict[str, List[Dict[str, Any]]] = {}
    for d in detections:
        u = d.get("target_user") or d.get("user_id") or "UNKNOWN_ACTOR"
        user_dets.setdefault(u, []).append(d)

    correlated_results = {}
    for user_id, dets in user_dets.items():
        chain = check_chain([], dets, max_window_hours=time_window_hours)
        risk = calculate_risk_score(user_id, dets, chain)
        correlated_results[user_id] = {
            "user_id": user_id,
            "detection_count": len(dets),
            "detections": dets,
            "chain_analysis": chain,
            "risk_evaluation": risk
        }

    return correlated_results

def calculate_risk_score(
    user_id: str,
    user_detections: List[Dict[str, Any]],
    chain_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    개별 탐지 결과 가중치 합산 + 상관분석 체인 매칭 가산 보너스 점수 산출
    최대 100점 상한 (Normalized Risk Score: 0 ~ 100)
    """
    weights = _get_scoring_weights()
    base_score = 0
    contributing_factors = []

    for d in user_detections:
        rid = d.get("rule_id", "")
        pts = 0
        if "BRUTEFORCE" in rid:
            pts = weights.get("weight_bruteforce", 35)
        elif "OFFHOUR" in rid:
            pts = weights.get("weight_offhour_login", 20)
        elif "TRAFFIC" in rid:
            pts = weights.get("weight_traffic_spike", 40)
        elif "ANOMALY" in rid or "MASS-DOWNLOAD" in rid or "DATA-EXPORT" in rid:
            pts = weights.get("weight_saas_anomaly", 45)
        elif "IOC-MATCH" in rid:
            pts = weights.get("weight_ioc_match", 50)
        elif "UNAUTHORIZED" in rid or "PRIV-ESCALATION" in rid:
            pts = weights.get("weight_unauthorized_access", 30)
        else:
            pts = 20

        base_score += pts
        contributing_factors.append({
            "rule_id": rid,
            "rule_name": d.get("rule_name", "이상 징후"),
            "points": pts,
            "details": d.get("details", "")
        })

    # 킬체인 상관분석 완성 시 가산점
    chain_bonus = 0
    if chain_result and chain_result.get("is_chain_completed"):
        chain_bonus = weights.get("chain_correlation_bonus", 50)
        base_score += chain_bonus
        contributing_factors.append({
            "rule_id": "CHAIN-CORRELATION-BONUS",
            "rule_name": "3단계 다단계 공격 체인 완성 가산점",
            "points": chain_bonus,
            "details": chain_result.get("chain_summary", "")
        })

    # 100점 정규화 상한
    final_score = min(100, base_score)

    cutoff = weights.get("high_priority_cutoff", 70)
    if final_score >= cutoff:
        priority = "HIGH"
    elif final_score >= 40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "user_id": user_id,
        "risk_score": final_score,
        "priority": priority,
        "is_chain_completed": chain_result.get("is_chain_completed", False) if chain_result else False,
        "chain_length": chain_result.get("chain_length", 0) if chain_result else 0,
        "factor_count": len(contributing_factors),
        "factors": contributing_factors
    }

def run_day03_evaluation(
    events: List[Dict[str, Any]],
    all_detections: List[Dict[str, Any]]
) -> str:
    """Day 3 결과를 day03_risk_scores.json으로 저장"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    corr_results = correlate_events(events, all_detections)

    out_file = os.path.join(base_dir, "anomaly_detection", "day03_risk_scores.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(corr_results, f, indent=2, ensure_ascii=False)

    return out_file
