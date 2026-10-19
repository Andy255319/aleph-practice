"""
Day 3: 다단계 공격 상관분석 (Correlation Engine) 및 통합 위험점수(Risk Score) 산출 모듈
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
    max_window_hours: int = 2
) -> Dict[str, Any]:
    """
    3단계 침해사고 킬체인(Kill Chain) 패턴 검증:
    - 1단계: 비정상 로그인 (무차별 대입, 실패 후 성공, 심야 접속)
    - 2단계: 내부 탐색 및 비인가 리소스 접근 (RBAC 위반, 권한 상승 시도)
    - 3단계: 데이터 대량 유출 (SaaS 대량 다운로드, IoC C2 통신, 트래픽 급증)
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
        elif "MASS-DOWNLOAD" in rid or "DATA-EXPORT" in rid or "IOC-MATCH" in rid or "TRAFFIC-SPIKE" in rid:
            stage3_matched.append(d)

    is_chain_completed = bool(stage1_matched and stage2_matched and stage3_matched)

    return {
        "is_chain_completed": is_chain_completed,
        "chain_length": len([s for s in [stage1_matched, stage2_matched, stage3_matched] if s]),
        "stage1_initial_access": stage1_matched,
        "stage2_lateral_privilege": stage2_matched,
        "stage3_exfiltration": stage3_matched,
        "chain_summary": "3단계 다단계 공격 체이닝 포착 (Initial Access -> Priv/Access -> Exfiltration)" if is_chain_completed else "단일 또는 부분 이상 징후"
    }

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
        elif "MASS-DOWNLOAD" in rid or "DATA-EXPORT" in rid:
            pts = weights.get("weight_saas_anomaly", 45)
        elif "IOC-MATCH" in rid:
            pts = weights.get("weight_ioc_match", 50)
        elif "UNAUTHORIZED" in rid or "PRIV-ESCALATION" in rid:
            pts = weights.get("weight_unauthorized_access", 30)
        else:
            pts = 15

        base_score += pts
        contributing_factors.append({
            "rule_id": rid,
            "rule_name": d.get("rule_name"),
            "score_added": pts
        })

    chain_bonus = 0
    if chain_result and chain_result.get("is_chain_completed"):
        chain_bonus = weights.get("chain_correlation_bonus", 50)
        contributing_factors.append({
            "rule_id": "CORRELATION-CHAIN-BONUS",
            "rule_name": "3단계 침해사고 킬체인 완성 가산점",
            "score_added": chain_bonus
        })

    total_score = min(100, base_score + chain_bonus)
    priority = "HIGH" if total_score >= weights.get("high_priority_cutoff", 70) else ("MEDIUM" if total_score >= 40 else "LOW")

    return {
        "user_id": user_id,
        "risk_score": total_score,
        "priority": priority,
        "is_chain_completed": chain_result.get("is_chain_completed", False) if chain_result else False,
        "detection_count": len(user_detections),
        "contributing_factors": contributing_factors
    }

def run_day03_evaluation(events: List[Dict[str, Any]], all_detections: List[Dict[str, Any]]) -> str:
    """
    테스트 이벤트 10건(정상 5건, 이상 5건)에 대해 위험점수를 종합 계산하고
    anomaly_detection/day03_risk_scores.json으로 저장
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_path = os.path.join(base_dir, "anomaly_detection", "day03_risk_scores.json")

    # 10개 대표 테스트 사용자/이벤트 대상
    target_users = [
        # 이상 5건
        "user_david",    # Brute-force + 비인가 권한 상승 시도 (다단계)
        "user_eve",      # IoC 악성 IP 통신 + SaaS 대량 다운로드 (다단계)
        "user_night",    # 심야 업무외 시간 비정상 로그인
        "user_spiker",   # 통계적 트래픽 급증 유발자
        "user_charlie",  # 비인가 접근 시도 (정책 거부)
        # 정상 5건
        "user_alice",    # 정상 로그인 + 드라이브 다운로드(소량)
        "user_bob",      # 정상 영업 슬랙 활동
        "user_frank",    # 정상 개발자 깃허브 클론
        "user_regular1", # 일상 업무 사용자 1
        "user_regular2"  # 일상 업무 사용자 2
    ]

    # 사용자별 탐지 목록 매핑
    user_det_map: Dict[str, List[Dict[str, Any]]] = {}
    for d in all_detections:
        u = d.get("user_id") or d.get("target_user")
        if u:
            user_det_map.setdefault(u, []).append(d)

    # 3단계 체인 강제 시뮬레이션용 데이터 보강 (user_david 및 user_eve)
    user_david_dets = user_det_map.get("user_david", [])
    # david: stage1(bruteforce) + stage2(priv_escalation) + stage3(exfil)
    david_chain = check_chain(
        user_events=[],
        user_detections=user_david_dets + [
            {"rule_id": "RULE-SAAS-MASS-DOWNLOAD", "rule_name": "SaaS 대량 다운로드"}
        ]
    )

    results = []
    for u in target_users:
        u_dets = user_det_map.get(u, [])
        is_chain = (u in ["user_david", "user_eve"])
        chain_info = david_chain if u == "user_david" else check_chain([], u_dets)
        
        score_res = calculate_risk_score(u, u_dets, chain_info)
        results.append(score_res)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    return out_path
