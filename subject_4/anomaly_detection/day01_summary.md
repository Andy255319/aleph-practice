# Day 1: 로그 정규화 및 데이터 무결성 요약 보고서

- 생성 시각: 2026-10-19 12:46:35

## 1. 정제 전/후 건수 비교 (실습 교재 데이터셋 기준)

| 로그 소스 | 원본 건수 | 정제 후 정규화 건수 | 제외 건수 (결측치 / 이상 타임스탬프) |
| :--- | :---: | :---: | :---: |
| 로그인 감사 로그 (`login_logs_practice.csv`) | 10 | 7 | 3건 (user/ip 누락 2건, not-a-time 1건) |
| 방화벽 트래픽 로그 (`firewall_logs_practice.csv`) | 10 | 7 | 3건 (src_ip/dst_ip 누락 2건, not-a-time 1건) |
| SaaS 클라우드 로그 (`saas_logs_practice.csv`) | 10 | 8 | 2건 (user 누락 1건, not-a-time 1건) |
| **총합계** | **30** | **22** | **8건** |

## 2. 주요 정제 및 정규화 특징
1. **타임스탬프 다형성 지원**: `2026/10/05`와 `2026-10-05` 형식을 통합 파싱하여 ISO-8601로 일원화
2. **비정상 문자열 제거**: `not-a-time` 결측 타임스탬프 자동 필터링
3. **공통 스키마 규격화**: `event_id`, `timestamp`, `event_source`, `user_id`, `source_ip`, `action`, `status`, `details` 8개 필드로 통일
