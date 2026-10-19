# Day 4 False Positive (오탐) 사례 정밀 분석 보고서

- **분석 일시**: 2026-10-19 12:01:59
- **초기 오탐 발생 건수**: 총 4건

## 1. 식별된 대표 오탐(False Positive) 3건 및 원인 분석

### [사례 1] 정기 자동화 배치 계정의 심야 로그인 (`TEST-NORM-07`)
- **대상 계정**: `user_night_batch` (23시 접속)
- **오탐 원인**: 단순 22시~06시 시각 조건만으로 일괄 차단하여, 사전 승인된 야간 시스템 배치 계정까지 침해로 오인.
- **개선 방안**: `config/detection_thresholds.json`에 `batch_whitelisted_accounts` 목록을 추가하여 예외 처리.

### [사례 2] 정기 데이터베이스 백업 트래픽의 스파이크 오인 (`TEST-NORM-08`)
- **대상 계정/서비스**: `user_backup_service` (새벽 3시 25MB 전송)
- **오탐 원인**: 대량 데이터 전송량(10MB 초과)만으로 무조건 DDoS/유출로 분류.
- **개선 방안**: 백업 데몬 전용 IP 및 예약된 백업 시간 윈도우에 대한 트래픽 룰 예외 조건 부여.

### [사례 3] 임시 권한 승인 사용자의 정상 리소스 접근 오인 (`TEST-NORM-04`, `TEST-NORM-05`)
- **대상 사용자**: `user_charlie` (Salesforce 접근), `user_alice` (Confluence 접근)
- **오탐 원인**: 3과목 `access_control/policy.py`의 `APPROVED_EXCEPTIONS` 결재 내역을 연동하지 않고 정적 RBAC만 검사하여 오탐 발생.
- **개선 방안**: `evaluate_access()` 호출 시 예외 승인(`exception_applied == True`) 결과를 반영하여 정상 처리.
