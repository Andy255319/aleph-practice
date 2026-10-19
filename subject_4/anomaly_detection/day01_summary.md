# Day 1 로그 데이터셋 탐색 및 정규화 결과 보고서

- **실행 일시**: 2026-10-19 12:01:59
- **정규화 산출물**: `C:\Users\user\Desktop\aleph\aleph=practice\subject_4\anomaly_detection\normalized_events.json`

## 1. 정규화 전/후 데이터 건수 비교

| 로그 소스 | 원본 건수 | 정제/정규화 후 건수 | 결측/이상 정제 건수 | 정제 사유 |
|---|---|---|---|---|
| **로그인 로그 (Login)** | 15건 | 13건 | 2건 | 사용자 ID 누락(1건), 타임스탬프 오류 `2026-99-99`(1건) |
| **방화벽 로그 (Firewall)** | 10건 | 9건 | 1건 | 출발지 IP 결측(1건) |
| **SaaS 감사 로그 (SaaS)** | 7건 | 6건 | 1건 | 수행자(actor) 결측(1건) |
| **합계** | **32건** | **28건** | **4건** | 전체 무결성 보증 완료 |

## 2. 공통 스키마 규격 (Standard Schema)
모든 이종 로그는 아래 7대 표준 필드로 단일화되었습니다:
- `event_id`: 이벤트 고유 식별자 (UUID)
- `timestamp`: ISO-8601 표준 타임스탬프
- `event_source`: 소스 분류 (login, firewall, saas)
- `user_id`: 사용자 식별자
- `source_ip`: 인입 IP 주소
- `action`: 수행 작업
- `status`: 처리 결과 (SUCCESS, FAIL, ALLOW, DENY)
- `details`: 소스별 특화 세부 메타데이터 (포트, 바이트량, SaaS 앱명 등)
