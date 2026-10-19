"""
Day 1 Step 1: 샘플 로그 데이터셋 탐색 및 결측치/이상치 분석 스크립트
"""
import os
import pandas as pd
from typing import Dict, Any

def get_data_dir() -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "data")

def explore_csv_file(file_path: str, timestamp_col: str) -> Dict[str, Any]:
    """CSV 파일 읽기 및 결측치, 타임스탬프 무결성 탐색"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")

    df = pd.read_csv(file_path)
    total_rows = len(df)
    missing_counts = df.isnull().sum().to_dict()
    missing_ratio = {k: v / total_rows for k, v in missing_counts.items()} if total_rows > 0 else {}

    # 타임스탬프 유효성 검사 (이상치 비율 산출)
    parsed_ts = pd.to_datetime(df[timestamp_col], errors='coerce')
    invalid_ts_count = int(parsed_ts.isnull().sum())
    invalid_ts_ratio = invalid_ts_count / total_rows if total_rows > 0 else 0.0

    return {
        "file_name": os.path.basename(file_path),
        "total_rows": total_rows,
        "columns": list(df.columns),
        "missing_counts": missing_counts,
        "missing_ratio": missing_ratio,
        "invalid_timestamp_count": invalid_ts_count,
        "invalid_timestamp_ratio": invalid_ts_ratio,
        "sample_head": df.head(3).to_dict(orient="records")
    }

def explore_all_logs() -> Dict[str, Any]:
    data_dir = get_data_dir()
    login_stats = explore_csv_file(os.path.join(data_dir, "login_logs.csv"), "timestamp")
    fw_stats = explore_csv_file(os.path.join(data_dir, "firewall_logs.csv"), "event_time")
    saas_stats = explore_csv_file(os.path.join(data_dir, "saas_logs.csv"), "record_time")

    return {
        "login_logs": login_stats,
        "firewall_logs": fw_stats,
        "saas_logs": saas_stats
    }

if __name__ == "__main__":
    results = explore_all_logs()
    print("=== 탐색 분석 결과 ===")
    for k, v in results.items():
        print(f"[{k}] 총 행수: {v['total_rows']}, 결측치: {v['missing_counts']}, 이상 타임스탬프: {v['invalid_timestamp_count']}")
