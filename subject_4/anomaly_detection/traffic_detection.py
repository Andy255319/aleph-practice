"""
Day 2: 네트워크 트래픽 급증(Traffic Spike) 통계 기반 이상탐지 모듈
(Day 4 슬라이드 표 명세 반영:
 - detect_traffic_spike(): 시간대별 트래픽 데이터 필요 (여러 시점의 데이터 필요))
"""
import os
import json
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

def _get_thresholds() -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "detection_thresholds.json")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f).get("traffic_detection", {})
    return {
        "window_minutes": 5,
        "spike_connection_threshold": 2,
        "baseline_sigma_multiplier": 2.0,
        "min_bytes_threshold": 10000000
    }

def aggregate_traffic_by_time_bucket(
    events: List[Dict[str, Any]],
    bucket_minutes: int = 5
) -> Dict[str, Dict[str, Any]]:
    """
    [여러 시점의 데이터 집계]:
    방화벽 이벤트를 시간대별(기본 5분 버킷)로 집계하여 시점별 연결 수 및 전송량 산출
    """
    fw_events = [e for e in events if e.get("event_source") == "firewall"]
    buckets: Dict[str, Dict[str, Any]] = {}

    for e in fw_events:
        dt = datetime.fromisoformat(e["timestamp"])
        # 버킷 키 계산 (예: 2026-10-05 09:00:00)
        minute_bucket = (dt.minute // bucket_minutes) * bucket_minutes
        bucket_dt = dt.replace(minute=minute_bucket, second=0, microsecond=0)
        bucket_key = bucket_dt.strftime("%Y-%m-%d %H:%M")

        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "bucket_time": bucket_key,
                "connection_count": 0,
                "bytes_transferred": 0,
                "source_ips": set(),
                "events": []
            }

        buckets[bucket_key]["connection_count"] += 1
        b_val = e.get("details", {}).get("bytes_transferred", 1500)
        buckets[bucket_key]["bytes_transferred"] += b_val
        buckets[bucket_key]["source_ips"].add(e.get("source_ip", "unknown"))
        buckets[bucket_key]["events"].append(e)

    return buckets

def calculate_traffic_baseline(events: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    [시간대별 트래픽 데이터의 베이스라인 통계 산출]:
    여러 시점의 트래픽 버킷 데이터를 기반으로 평시 평균 연결 수와 표준편차를 계산
    """
    buckets = aggregate_traffic_by_time_bucket(events)
    if not buckets:
        return {"mean_connections": 1.0, "std_connections": 0.0, "mean_bytes": 1500.0, "std_bytes": 0.0}

    conn_counts = [b["connection_count"] for b in buckets.values()]
    bytes_counts = [b["bytes_transferred"] for b in buckets.values()]

    return {
        "mean_connections": float(np.mean(conn_counts)),
        "std_connections": float(np.std(conn_counts)),
        "mean_bytes": float(np.mean(bytes_counts)),
        "std_bytes": float(np.std(bytes_counts)),
        "total_buckets": len(buckets)
    }

def detect_traffic_spike(
    events: List[Dict[str, Any]],
    baseline: Optional[Dict[str, float]] = None,
    window_minutes: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    트래픽 급증(Traffic Spike) 탐지:
    [평가 시 고려할 점]: 단일 시점의 로그 하나로는 급증 여부를 알 수 없으므로 '여러 시점의 데이터'가 필요함.
    시간대별(버킷별) 트래픽 발생량과 전체 시점 베이스라인을 비교하여,
    임계치 또는 통계적 이상치를 초과하는 시점의 트래픽 급증을 탐지.
    """
    cfg = _get_thresholds()
    win_min = window_minutes if window_minutes is not None else cfg.get("window_minutes", 5)
    sigma_mult = cfg.get("baseline_sigma_multiplier", 2.0)
    min_conn_thresh = cfg.get("spike_connection_threshold", 2)

    if baseline is None:
        baseline = calculate_traffic_baseline(events)

    buckets = aggregate_traffic_by_time_bucket(events, bucket_minutes=win_min)
    detections = []

    # 동적 연결 수 임계치 (평균 + 2*sigma 또는 최소 임계치)
    effective_conn_threshold = max(
        baseline["mean_connections"] + (sigma_mult * baseline["std_connections"]),
        float(min_conn_thresh)
    )

    for b_key, b_info in buckets.items():
        conn_cnt = b_info["connection_count"]
        # 1. 연결 빈도 급증 (단시간 집중 포트 스캐닝 등)
        if conn_cnt >= effective_conn_threshold:
            # 주요 유발 IP 식별
            ip_counts = {}
            for ev in b_info["events"]:
                ip = ev.get("source_ip", "unknown")
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            top_ip = max(ip_counts, key=ip_counts.get) if ip_counts else "unknown"

            detections.append({
                "rule_id": "RULE-TRAFFIC-SPIKE",
                "rule_name": "시간대별 트래픽 다중 시점 비교 기반 급증(Spike) 탐지",
                "time_bucket": b_key,
                "source_ip": top_ip,
                "all_source_ips": list(b_info["source_ips"]),
                "connection_count": conn_cnt,
                "baseline_mean": round(baseline["mean_connections"], 2),
                "threshold": round(effective_conn_threshold, 2),
                "severity": "HIGH",
                "details": f"시간대 [{b_key}]에 평시 평균({baseline['mean_connections']:.1f}건)을 초과하는 {conn_cnt}건의 트래픽 급증 탐지 (여러 시점 비교 평가)"
            })

        # 2. 바이트 전송량 급증 (대량 유출/DDoS 지원)
        min_bytes = cfg.get("min_bytes_threshold", 10000000)
        if b_info["bytes_transferred"] >= min_bytes:
            detections.append({
                "rule_id": "RULE-TRAFFIC-SPIKE-BYTES",
                "rule_name": "대용량 바이트 전송 트래픽 급증 탐지",
                "time_bucket": b_key,
                "source_ip": list(b_info["source_ips"])[0] if b_info["source_ips"] else "unknown",
                "bytes_transferred": b_info["bytes_transferred"],
                "severity": "CRITICAL",
                "details": f"단일 윈도우 내 {b_info['bytes_transferred']:,} Bytes 대량 트래픽 전송 포착"
            })

    return detections

def generate_day02_result(
    events: List[Dict[str, Any]],
    bruteforce_results: List[Dict[str, Any]],
    offhour_results: List[Dict[str, Any]],
    traffic_results: List[Dict[str, Any]],
    baseline: Dict[str, float]
) -> str:
    """Day 2 검증 결과를 day02_result.md로 생성"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_path = os.path.join(base_dir, "anomaly_detection", "day02_result.md")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("# Day 2: 로그인 및 네트워크 트래픽 이상탐지 검증 보고서\n\n")
        f.write(f"- 생성 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## 1. 슬라이드 명세 평가 특성 반영\n")
        f.write("- **detect_bruteforce()**: 단일 로그로 판단 불가 -> 사용자별 시간 윈도우 내 다중 실패 집계로 평가\n")
        f.write("- **detect_offhour_login()**: 개별 이벤트 평가 가능 -> 단일 로그의 타임스탬프 심야 시간대(22:00~06:00) 즉시 판정\n")
        f.write("- **detect_traffic_spike()**: 여러 시점의 데이터 필요 -> 시간대별 버킷 집계 및 전체 시점 통계 베이스라인 비교\n\n")
        f.write("## 2. 세부 탐지 결과 요약\n\n")
        f.write(f"- **무차별 대입(Brute-force) 탐지**: {len(bruteforce_results)}건 식별\n")
        for d in bruteforce_results:
            f.write(f"  - 대상: `{d['target_user']}` ({d['source_ip']}) | 실패 횟수: {d['fail_count']}회 | 탈취 성공 여부: {d.get('consecutive_success')}\n")
        f.write(f"- **업무 외 시간(심야) 로그인 탐지**: {len(offhour_results)}건 식별\n")
        for d in offhour_results:
            f.write(f"  - 대상: `{d['target_user']}` ({d['source_ip']}) | 시각: {d['timestamp']}\n")
        f.write(f"- **트래픽 급증(Spike) 탐지**: {len(traffic_results)}건 식별\n")
        for d in traffic_results:
            f.write(f"  - 시점: `{d['time_bucket']}` | 출발지: `{d['source_ip']}` | 연결수: {d.get('connection_count', 0)}건\n")

    return out_path
