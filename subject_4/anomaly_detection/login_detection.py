"""
Day 2: 로그인 기반 이상 징후 탐지 모듈 (무차별 대입 및 업무 외 시간 로그인)
(Day 4 슬라이드 표 명세 반영:
 - detect_bruteforce(): 사용자별 로그인 로그와 시간 범위 필요 (단일 로그 한 건만으로 판단 불가)
 - detect_offhour_login(): 로그인 로그 한 건으로 개별 이벤트 평가 가능)
"""
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

def _get_thresholds() -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "detection_thresholds.json")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f).get("login_detection", {})
    return {
        "bruteforce_fail_threshold": 2,
        "bruteforce_window_minutes": 5,
        "offhour_start_hour": 22,
        "offhour_end_hour": 6
    }

def detect_bruteforce(
    events: List[Dict[str, Any]],
    threshold: Optional[int] = None,
    window_minutes: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    무차별 대입(Brute-force) 탐지:
    [평가 시 고려할 점]: 단일 로그 한 건만으로는 브루트포스 여부를 판단하기 어려움.
    따라서 '사용자별 로그인 로그'를 추출하고, 지정된 '시간 범위(window_minutes)' 내에서
    실패(FAIL) 이벤트를 시계열 집계하여 threshold 이상 발생 시 탐지.
    특히 실패 직후 로그인 성공(SUCCESS)이 뒤따르는 경우 '계정 탈취 성공(Account Takeover)'으로 가중 평가.
    """
    cfg = _get_thresholds()
    fail_threshold = threshold if threshold is not None else cfg.get("bruteforce_fail_threshold", 2)
    win_min = window_minutes if window_minutes is not None else cfg.get("bruteforce_window_minutes", 5)

    login_events = [e for e in events if e.get("event_source") == "login"]
    
    # 사용자별 로그인 이벤트 그룹화
    user_events: Dict[str, List[Dict[str, Any]]] = {}
    for e in login_events:
        u = e.get("user_id")
        if u and u != "N/A":
            user_events.setdefault(u, []).append(e)

    detections = []

    for user_id, u_evts in user_events.items():
        sorted_evts = sorted(u_evts, key=lambda x: x["timestamp"])
        n = len(sorted_evts)

        for i in range(n):
            current_evt = sorted_evts[i]
            if current_evt.get("status") != "FAIL":
                continue

            current_time = datetime.fromisoformat(current_evt["timestamp"])
            window_end = current_time + timedelta(minutes=win_min)

            # 시간 범위(윈도우) 내 실패 이벤트 수집
            fails_in_window = []
            for j in range(i, n):
                t_j = datetime.fromisoformat(sorted_evts[j]["timestamp"])
                if t_j <= window_end:
                    if sorted_evts[j].get("status") == "FAIL":
                        fails_in_window.append(sorted_evts[j])
                else:
                    break

            if len(fails_in_window) >= fail_threshold:
                # 실패 직후 성공 여부 확인 (계정 탈취 포착)
                next_success = any(
                    sorted_evts[k].get("status") == "SUCCESS" and 
                    datetime.fromisoformat(sorted_evts[k]["timestamp"]) <= window_end + timedelta(minutes=2)
                    for k in range(i, min(i + len(fails_in_window) + 2, n))
                )

                detections.append({
                    "rule_id": "RULE-LOGIN-BRUTEFORCE",
                    "rule_name": "다중 로그인 실패 기반 Brute-force 탐지",
                    "target_user": user_id,
                    "source_ip": fails_in_window[0].get("source_ip"),
                    "window_start": fails_in_window[0]["timestamp"],
                    "window_end": fails_in_window[-1]["timestamp"],
                    "fail_count": len(fails_in_window),
                    "threshold": fail_threshold,
                    "consecutive_success": next_success,
                    "severity": "CRITICAL" if next_success else "HIGH",
                    "details": f"{win_min}분 윈도우 내 {len(fails_in_window)}회 로그인 실패 감지" + (" (이후 로그인 성공 포착: 계정 탈취 위험)" if next_success else "")
                })
                break  # 해당 사용자에 대해 보고 완료 후 다음 사용자로

    return detections

def is_offhour_single_event(
    event: Dict[str, Any],
    start_hour: int = 22,
    end_hour: int = 6
) -> bool:
    """단일 로그인 로그 한 건에 대해 업무 외 시간 여부 개별 평가"""
    if event.get("event_source") != "login":
        return False
    dt = datetime.fromisoformat(event["timestamp"])
    hour = dt.hour
    if start_hour > end_hour:
        return hour >= start_hour or hour < end_hour
    return start_hour <= hour < end_hour

def detect_offhour_login(
    events: List[Dict[str, Any]],
    start_hour: Optional[int] = None,
    end_hour: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    업무 외 시간(심야/새벽) 로그인 탐지:
    [평가 시 고려할 점]: 로그인 로그 단 '한 건'만으로도 개별 이벤트 단위의 즉각적인 평가가 가능함.
    설정된 야간 시간대(기본 22:00 ~ 06:00)에 발생한 로그인 성공 이벤트를 개별 필터링.
    """
    cfg = _get_thresholds()
    s_hour = start_hour if start_hour is not None else cfg.get("offhour_start_hour", 22)
    e_hour = end_hour if end_hour is not None else cfg.get("offhour_end_hour", 6)

    login_events = [e for e in events if e.get("event_source") == "login"]
    detections = []

    for e in login_events:
        if is_offhour_single_event(e, s_hour, e_hour) and e.get("status") == "SUCCESS":
            dt = datetime.fromisoformat(e["timestamp"])
            detections.append({
                "rule_id": "RULE-LOGIN-OFFHOUR",
                "rule_name": "업무 외 시간(심야) 비인가 로그인 탐지",
                "event_id": e.get("event_id"),
                "target_user": e.get("user_id"),
                "source_ip": e.get("source_ip"),
                "timestamp": e.get("timestamp"),
                "access_hour": dt.hour,
                "offhour_range": f"{s_hour}:00 ~ {e_hour}:00",
                "severity": "MEDIUM",
                "details": f"심야 업무 외 시간({dt.strftime('%H:%M:%S')})에 로그인 성공 이벤트 포착 (개별 평가)"
            })

    return detections
