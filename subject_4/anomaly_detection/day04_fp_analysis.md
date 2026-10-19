# Day 4: 오탐(False Positive) 원인 정밀 분석 보고서

- 생성 시각: 2026-10-19 12:46:35

## 1. 튜닝 전 발견된 주요 오탐(FP) 4대 사례

### 사례 1: [TEST-NORM-01] 사용자 `kim` (login)
- 대상 리소스: `drive`
- 오탐 발생 사유: 단순 비밀번호 1회 오타 후 바로 성공
- **슬라이드 평가 명세 기반 개선책**: `detect_bruteforce()`에 단일 로그 평가 금지 원칙 적용 -> 시간 윈도우 내 연속 실패 임계값(2회 이상) 설정

### 사례 2: [TEST-NORM-04] 사용자 `user_night_batch` (login)
- 대상 리소스: `BatchDB`
- 오탐 발생 사유: 사전 등록된 야간 정기 배치 정상 계정
- **슬라이드 평가 명세 기반 개선책**: `detect_offhour_login()`에 사전 승인된 정기 야간 배치/점검 계정 화이트리스트 필터링 추가

### 사례 3: [TEST-NORM-05] 사용자 `choi` (login)
- 대상 리소스: `login_offhour`
- 오탐 발생 사유: 사전 승인된 야간 시스템 패치 작업자
- **슬라이드 평가 명세 기반 개선책**: `detect_offhour_login()`에 사전 승인된 정기 야간 배치/점검 계정 화이트리스트 필터링 추가

### 사례 4: [TEST-NORM-06] 사용자 `user_backup_service` (db_backup)
- 대상 리소스: `BackupSrv`
- 오탐 발생 사유: 새벽 정기 백업 전송 트래픽
- **슬라이드 평가 명세 기반 개선책**: `detect_traffic_spike()`에 여러 시점 비교 및 정기 백업 서비스 대역폭 예외 등록

### 사례 5: [TEST-NORM-07] 사용자 `user_charlie` (view_lead)
- 대상 리소스: `Salesforce`
- 오탐 발생 사유: 기술지원을 위해 사전 예외 승인된 Salesforce 접근
- **슬라이드 평가 명세 기반 개선책**: `detect_unauthorized_access()`에 3과목 `APPROVED_EXCEPTIONS` 예외 승인 정책 연동

### 사례 6: [TEST-NORM-08] 사용자 `user_alice` (read_wiki)
- 대상 리소스: `Confluence`
- 오탐 발생 사유: 마케팅 위키 작성을 위해 사전 승인된 Confluence 접근
- **슬라이드 평가 명세 기반 개선책**: `detect_unauthorized_access()`에 3과목 `APPROVED_EXCEPTIONS` 예외 승인 정책 연동

