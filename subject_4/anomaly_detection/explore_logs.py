"""
Day 1 Step 1: 샘플 로그 데이터셋 탐색 및 결측치/이상치 분석 스크립트
(login_logs_practice.csv, firewall_logs_practice.csv, saas_logs_practice.csv)
"""
import os
import pandas as pd
from typing import Dict, Any

def get_data_dir() -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "data")

def resolve_csv_path(filename_preferred: str, fallback_filename: str) -> str:
    data_dir = get_data_dir()
    pref_path = os.path.join(data_dir, filename_preferred)
    if os.path.exists(pref_path):
        return pref_path
    return os.path.join(data_dir, fallback_filename)

def explore_csv_file(file_path: str, timestamp_col: str = "timestamp") -> Dict[str, Any]:
    """CSV 파일 읽기 및 결측치, 타임스탬프 무결성 탐색"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")

    df = pd.read_csv(file_path)
    total_rows = len(df)
    missing_counts = df.isnull().sum().to_dict()
    missing_ratio = {k: round(v / total_rows, 4) for k, v in missing_counts.items()} if total_rows > 0 else {}

    # 타임스탬프 유효성 검사 (이상치 비율 산출)
    # pd.to_datetime은 '2026/10/05' 같은 포맷은 자동 변환하고 'not-a-time'은 NaT로 변환함
    parsed_ts = pd.to_datetime(df[timestamp_col], errors='coerce')
    invalid_ts_count = int(parsed_ts.isnull().sum())
    invalid_ts_ratio = round(invalid_ts_count / total_rows, 4) if total_rows > 0 else 0.0

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
    login_path = resolve_csv_path("login_logs_practice.csv", "login_logs.csv")
    fw_path = resolve_csv_path("firewall_logs_practice.csv", "firewall_logs.csv")
    saas_path = resolve_csv_path("saas_logs_practice.csv", "saas_logs.csv")

    login_stats = explore_csv_file(login_path, "timestamp")
    fw_stats = explore_csv_file(fw_path, "timestamp")
    saas_stats = explore_csv_file(saas_path, "timestamp")

    return {
        "login_logs": login_stats,
        "firewall_logs": fw_stats,
        "saas_logs": saas_stats
    }

if __name__ == "__main__":
    results = explore_all_logs()
    print("=== Day 1: 샘플 로그 데이터셋 탐색 결과 ===")
    for k, v in results.items():
        print(f"\n[{v['file_name']}] 총 행수: {v['total_rows']}")
        print(f"  - 컬럼: {v['columns']}")
        print(f"  - 결측치: {v['missing_counts']}")
        print(f"  - 이상 타임스탬프: {v['invalid_timestamp_count']}건 (비율: {v['invalid_timestamp_ratio']*100:.1f}%)")
