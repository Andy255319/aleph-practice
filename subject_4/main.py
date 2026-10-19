"""
Subject 4: 이상탐지 자동화 전체 실습 (Day 1 ~ Day 5) 통합 실행 스크립트
(Day 1 ~ Day 4 슬라이드 및 실습 교재 명세 완벽 반영)
"""
import sys
import os
import json
from datetime import datetime

# Windows 콘솔 한글/유니코드 인코딩 설정
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# 패키지 경로 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from anomaly_detection.explore_logs import explore_all_logs
from anomaly_detection.normalize import run_normalization
from anomaly_detection.login_detection import detect_bruteforce, detect_offhour_login
from anomaly_detection.traffic_detection import calculate_traffic_baseline, detect_traffic_spike, generate_day02_result
from anomaly_detection.advanced_detection import detect_unauthorized_access, detect_saas_anomaly, match_ioc
from anomaly_detection.correlation import group_by_user, check_chain, calculate_risk_score, run_day03_evaluation, correlate_events
from anomaly_detection.evaluation import run_day04_tuning
from anomaly_detection.pipeline import run_anomaly_pipeline
from agent_core.tool_router import global_router

def main():
    print("\n" + "="*75)
    print(">>> [SUBJECT 4] 이상탐지 자동화 (Day 1 ~ Day 5) 실습 전체 파이프라인 가동")
    print("="*75)

    # -------------------------------------------------------------
    # DAY 1: 샘플 로그 데이터셋 탐색 및 전처리
    # -------------------------------------------------------------
    print("\n[DAY 1] 샘플 로그 데이터셋 탐색 및 공통 스키마 정규화 (120분)")
    explore_res = explore_all_logs()
    for k, v in explore_res.items():
        print(f"  - [{v['file_name']}] 원본: {v['total_rows']}행 | 결측치 컬럼: {list(v['missing_counts'].keys())} | 이상 타임스탬프: {v['invalid_timestamp_count']}건")

    norm_res = run_normalization()
    print(f"  -> 정규화 완료: 총 {norm_res['raw_counts']['total']}건 수집 -> 결측치/이상치 정제 후 {norm_res['clean_counts']['total']}건 통합 저장")
    print(f"  -> 산출물: {norm_res['output_file']}")
    print(f"  -> 산출물: {norm_res['summary_file']}")

    events = norm_res["events"]

    # -------------------------------------------------------------
    # DAY 2: 로그인 및 트래픽 탐지 룰 구현
    # -------------------------------------------------------------
    print("\n[DAY 2] 룰 및 베이스라인 기반 이상 징후 탐지 (로그인 / 트래픽)")
    bf_dets = detect_bruteforce(events)
    print(f"  - detect_bruteforce(): {len(bf_dets)}건 식별 (대상: {', '.join([d['target_user'] for d in bf_dets])}) [단일 로그 불가/시간 윈도우 평가]")

    off_dets = detect_offhour_login(events)
    print(f"  - detect_offhour_login(): {len(off_dets)}건 식별 (대상: {', '.join([d['target_user'] for d in off_dets])}) [개별 이벤트 즉시 평가]")

    baseline = calculate_traffic_baseline(events)
    print(f"  - 트래픽 통계 베이스라인: 평균 = {baseline['mean_connections']:.2f}건/버킷, 표준편차 = {baseline['std_connections']:.2f}")

    traffic_dets = detect_traffic_spike(events, baseline=baseline)
    print(f"  - detect_traffic_spike(): {len(traffic_dets)}건 식별 [시간대별 여러 시점 비교 평가]")

    day02_md = generate_day02_result(events, bf_dets, off_dets, traffic_dets, baseline)
    print(f"  -> 산출물: {day02_md}")

    # -------------------------------------------------------------
    # DAY 3: 고급 탐지 로직 및 상관분석 구현
    # -------------------------------------------------------------
    print("\n[DAY 3] 고급 탐지 (비인가 접근, SaaS 이상, IOC) 및 3단계 킬체인 상관분석")
    unauth_dets = detect_unauthorized_access(events)
    print(f"  - detect_unauthorized_access(): {len(unauth_dets)}건 식별 [접근 로그 및 권한 정책 평가 결과 변환]")

    saas_dets = detect_saas_anomaly(events)
    print(f"  - detect_saas_anomaly(): {len(saas_dets)}건 식별 [사용자별 정상 패턴 기준선 비교]")

    ioc_dets = match_ioc(events)
    print(f"  - match_ioc(): {len(ioc_dets)}건 식별 [IP·도메인과 IOC 목록 매칭 결과 변환]")

    all_dets = bf_dets + off_dets + traffic_dets + unauth_dets + saas_dets + ioc_dets
    day03_json = run_day03_evaluation(events, all_dets)
    print(f"  - correlate_events(): 사용자별 다단계 공격 킬체인 및 이벤트 관계 평가 완료")
    print(f"  -> 산출물: {day03_json}")

    # -------------------------------------------------------------
    # DAY 4: 기존 탐지룰 튜닝 (오탐 감소) (120분)
    # -------------------------------------------------------------
    print("\n[DAY 4] 기존 탐지룰 튜닝 (오탐 감소) (120분)")
    tuning_res = run_day04_tuning()
    b = tuning_res["before"]
    a = tuning_res["after"]
    print(f"  - 튜닝 전: Precision = {b['precision']*100:.1f}%, Recall = {b['recall']*100:.1f}%, FP(오탐) = {b['fp']}건")
    print(f"  - 튜닝 후: Precision = {a['precision']*100:.1f}%, Recall = {a['recall']*100:.1f}%, FP(오탐) = {a['fp']}건 (오탐 완전 제거)")
    print(f"  -> 산출물: {tuning_res['fp_analysis_path']}")
    print(f"  -> 산출물: {tuning_res['tuning_result_path']}")

    # -------------------------------------------------------------
    # DAY 5: AI 기반 이벤트 요약 · 우선순위 분류 자동화
    # -------------------------------------------------------------
    print("\n[DAY 5] End-to-End 통합 파이프라인 가동 및 AI 자연어 요약 보고서 생성")
    pipe_res = run_anomaly_pipeline()
    print(f"  - 총 식별된 위협 건수: {pipe_res['total_anomalies']}건")
    print(f"  - High 우선순위 위협: {pipe_res['high_priority_count']}건 AI 자동 분석 요약 완료")
    print(f"  - Agent Core 도구 등록 현황: {list(global_router.list_tools().keys())}")
    print(f"  -> 산출물: {pipe_res['report_json']}")
    print(f"  -> 산출물: {pipe_res['report_md']}")
    print(f"  -> 산출물: {pipe_res['retrospective_md']}")

    print("\n" + "="*75)
    print("[SUCCESS] Day 1 ~ Day 5 전체 실습 파이프라인 정상 가동 및 산출물 생성 완료!")
    print("="*75 + "\n")

if __name__ == "__main__":
    main()
