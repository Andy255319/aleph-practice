# [기술팀 상세 초동대응 리포트] evt-2001

- **보고서 발행 일시**: 2026-10-19 13:14:13
- **분류 등급**: CONFIDENTIAL - 보안기술팀 내부 공유용
- **인시던트 ID**: `evt-2001`
- **위협 수준(Severity)**: `HIGH`

---

## 1. 인시던트 핵심 개요 (Day 1 수집 데이터)
- **탐지 이벤트 유형**: `ABNORMAL_LOGIN`
- **공격 유입 출발지(Source IP)**: `203.0.113.25`
- **공격 표적 자산/계정(Target)**: `lee`
- **현재 처리 상태**: `CONTAINMENT`
- **적용 플레이북**: `N/A (PB-LOGIN-001)`
- **탐지 상세 설명**: 비정상 로그인 탐지

### 인시던트 수명주기 전이 이력
- **[2026-10-19T13:14:13.126205]** `detected` - None (담당: None)
- **[2026-10-19T13:14:13.126578]** `triaged` - 위험도 분석 및 분류 완료 (담당: SYSTEM)
- **[2026-10-19T13:14:13.184730]** `CONTAINMENT` - 격리 및 에스컬레이션 진행 (담당: SOAR_ENGINE)

---

## 2. 격리 및 차단 기술 조치 내역 (Day 2 조치 로그 연동)
총 `53`건의 자동 및 승인 기반 격리 조치가 시행되었습니다.

| 타임스탬프 | 조치 유형 | 대상 | 실행 결과 | 수행 주체 | 상세 내역 |
|---|---|---|---|---|---|
| 2026-10-19T12:18:31.165814 | `unlock_account` | `lee` | FAIL | 해제 사유 누락 (사유가 없거나 공백) |
| 2026-10-19T12:18:31.187185 | `lock_account` | `lee` | SUCCESS | 비정상 로그인 반복 |
| 2026-10-19T12:18:31.211242 | `block_ip` | `203.0.113.25` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:18:31.212173 | `terminate_session` | `lee` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:18:38.300367 | `lock_account` | `lee` | SUCCESS | 비정상 로그인 반복 |
| 2026-10-19T12:18:38.307476 | `block_ip` | `203.0.113.25` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:18:38.315865 | `terminate_session` | `lee` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:18:38.322821 | `unlock_account` | `lee` | FAIL | 해제 사유 누락 (사유가 없거나 공백) |
| 2026-10-19T12:18:38.329778 | `unlock_account` | `lee` | SUCCESS | 관제 분석 완료 후 정상 복구 |
| 2026-10-19T12:18:38.335982 | `unlock_account` | `lee` | SKIPPED | 이미 잠금 해제되었거나 잠금 상태가 아닌 계정 |
| 2026-10-19T12:18:38.341965 | `unblock_ip` | `203.0.113.25` | SUCCESS | 공격 소멸 확인 후 방화벽 롤백 |
| 2026-10-19T12:18:38.350169 | `terminate_session` | `lee` | SUCCESS | 자동화 세션 종료 |
| 2026-10-19T12:18:38.362811 | `unblock_ip` | `203.0.113.25` | SKIPPED | 이미 차단 해제되었거나 차단 목록에 없는 IP |
| 2026-10-19T12:23:30.054313 | `unlock_account` | `lee` | FAIL | 해제 사유 누락 (사유가 없거나 공백) |
| 2026-10-19T12:23:30.077763 | `lock_account` | `lee` | SUCCESS | 비정상 로그인 반복 |
| 2026-10-19T12:23:30.097913 | `block_ip` | `203.0.113.25` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:23:30.098966 | `terminate_session` | `lee` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:23:38.162327 | `lock_account` | `lee` | SUCCESS | 비정상 로그인 반복 |
| 2026-10-19T12:23:38.169960 | `block_ip` | `203.0.113.25` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:23:38.176869 | `terminate_session` | `lee` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:23:38.183328 | `unlock_account` | `lee` | FAIL | 해제 사유 누락 (사유가 없거나 공백) |
| 2026-10-19T12:23:38.190420 | `unlock_account` | `lee` | SUCCESS | 관제 분석 완료 후 정상 복구 |
| 2026-10-19T12:23:38.198231 | `unlock_account` | `lee` | SKIPPED | 이미 잠금 해제되었거나 잠금 상태가 아닌 계정 |
| 2026-10-19T12:23:38.204766 | `unblock_ip` | `203.0.113.25` | SUCCESS | 공격 소멸 확인 후 방화벽 롤백 |
| 2026-10-19T12:23:38.212033 | `terminate_session` | `lee` | SUCCESS | 자동화 세션 종료 |
| 2026-10-19T12:23:38.225222 | `unblock_ip` | `203.0.113.25` | SKIPPED | 이미 차단 해제되었거나 차단 목록에 없는 IP |
| 2026-10-19T12:47:54.744763 | `unlock_account` | `lee` | FAIL | 해제 사유 누락 (사유가 없거나 공백) |
| 2026-10-19T12:47:54.768071 | `lock_account` | `lee` | SUCCESS | 비정상 로그인 반복 |
| 2026-10-19T12:47:54.789548 | `block_ip` | `203.0.113.25` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:47:54.790777 | `terminate_session` | `lee` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:48:00.239739 | `lock_account` | `lee` | SUCCESS | 비정상 로그인 반복 |
| 2026-10-19T12:48:00.255387 | `block_ip` | `203.0.113.25` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:48:00.261455 | `terminate_session` | `lee` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T12:48:00.268266 | `unlock_account` | `lee` | FAIL | 해제 사유 누락 (사유가 없거나 공백) |
| 2026-10-19T12:48:00.274883 | `unlock_account` | `lee` | SUCCESS | 관제 분석 완료 후 정상 복구 |
| 2026-10-19T12:48:00.281823 | `unlock_account` | `lee` | SKIPPED | 이미 잠금 해제되었거나 잠금 상태가 아닌 계정 |
| 2026-10-19T12:48:00.288819 | `unblock_ip` | `203.0.113.25` | SUCCESS | 공격 소멸 확인 후 방화벽 롤백 |
| 2026-10-19T12:48:00.297542 | `terminate_session` | `lee` | SUCCESS | 자동화 세션 종료 |
| 2026-10-19T12:48:00.311862 | `unblock_ip` | `203.0.113.25` | SKIPPED | 이미 차단 해제되었거나 차단 목록에 없는 IP |
| 2026-10-19T12:49:42.482607 | `unlock_account` | `lee` | SKIPPED | 이미 잠금 해제되었거나 잠금 상태가 아닌 계정 |
| 2026-10-19T13:14:01.417087 | `unlock_account` | `lee` | FAIL | 해제 사유 누락 (사유가 없거나 공백) |
| 2026-10-19T13:14:01.447165 | `lock_account` | `lee` | SUCCESS | 비정상 로그인 반복 |
| 2026-10-19T13:14:01.469572 | `block_ip` | `203.0.113.25` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T13:14:01.470935 | `terminate_session` | `lee` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T13:14:13.126688 | `lock_account` | `lee` | SUCCESS | 비정상 로그인 반복 |
| 2026-10-19T13:14:13.142612 | `block_ip` | `203.0.113.25` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T13:14:13.149386 | `terminate_session` | `lee` | SUCCESS | 악성 IP에서 비정상 로그인 탐지 |
| 2026-10-19T13:14:13.156709 | `unlock_account` | `lee` | FAIL | 해제 사유 누락 (사유가 없거나 공백) |
| 2026-10-19T13:14:13.163509 | `unlock_account` | `lee` | SUCCESS | 관제 분석 완료 후 정상 복구 |
| 2026-10-19T13:14:13.170543 | `unlock_account` | `lee` | SKIPPED | 이미 잠금 해제되었거나 잠금 상태가 아닌 계정 |
| 2026-10-19T13:14:13.176959 | `unblock_ip` | `203.0.113.25` | SUCCESS | 공격 소멸 확인 후 방화벽 롤백 |
| 2026-10-19T13:14:13.184864 | `terminate_session` | `lee` | SUCCESS | 자동화 세션 종료 |
| 2026-10-19T13:14:13.198630 | `unblock_ip` | `203.0.113.25` | SKIPPED | 이미 차단 해제되었거나 차단 목록에 없는 IP |

---

## 3. ITSM 티켓 및 에스컬레이션 현황 (Day 3 연동 데이터)
- **발행 티켓 ID**: `TICK-20261019-4A4134`
- **티켓 상태**: `IN_PROGRESS`
- **현재 담당 엔지니어**: `security_manager`
- **티켓 제목**: [HIGH] ABNORMAL_LOGIN 대응 요청 - lee

### 티켓 처리 워크로그 및 SLA 추적
워크로그 없음

---

## 4. 침해 지표 (IoC) 및 방화벽 룰 현황
```json
{
  "indicators_of_compromise": [
    {"type": "ipv4", "value": "203.0.113.25", "action": "BLOCKED_ON_PERIMETER_FIREWALL"},
    {"type": "account", "value": "lee", "status": "LOCKED_OR_ISOLATED"}
  ]
}
```

## 5. 기술팀 후속 조치 과제
1. 호스트 포렌식 아티팩트(Prefetch, Event Log 4624/4625) 정밀 추출
2. 내부망 측면이동(Lateral Movement) 흔적 SIEM 상관분석 쿼리 수행
3. 외부 통신 악성 C2 도메인 DNS Sinkhole 등록 확인
