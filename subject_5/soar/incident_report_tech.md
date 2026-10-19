# [기술팀 상세 초동대응 리포트] INC-20261019-001

- **보고서 발행 일시**: 2026-10-19 11:49:16
- **분류 등급**: CONFIDENTIAL - 보안기술팀 내부 공유용
- **인시던트 ID**: `INC-20261019-001`
- **위협 수준(Severity)**: `HIGH`

---

## 1. 인시던트 핵심 개요 (Day 1 수집 데이터)
- **탐지 이벤트 유형**: `abnormal_login`
- **공격 유입 출발지(Source IP)**: `198.51.100.45`
- **공격 표적 자산/계정(Target)**: `user_john`
- **현재 처리 상태**: `CONTAINMENT`
- **적용 플레이북**: `비정상 로그인 대응 플레이북 (PB-001)`
- **탐지 상세 설명**: 동일 계정에 대해 해외 미인가 IP에서 5분간 12회 로그인 실패 후 로그인 성공 탐지

### 인시던트 수명주기 전이 이력
- **[2026-10-19T11:49:16.795381]** `NEW` - 인시던트 등록 완료 (담당: SYSTEM)
- **[2026-10-19T11:49:16.795522]** `ANALYZING` - 플레이북 수신 및 위협 인텔리전스 IP 평판 조회 시작 (담당: SOAR_ORCHESTRATOR)
- **[2026-10-19T11:49:16.824318]** `CONTAINMENT` - 일반계정 잠금, 세션 종료, IP 차단 등 1차 격리 완료 (담당: SOAR_ENGINE)

---

## 2. 격리 및 차단 기술 조치 내역 (Day 2 조치 로그 연동)
총 `6`건의 자동 및 승인 기반 격리 조치가 시행되었습니다.

| 타임스탬프 | 조치 유형 | 대상 | 실행 결과 | 수행 주체 | 상세 내역 |
|---|---|---|---|---|---|
| 2026-10-19T11:48:57.351298 | `lock_account` | `user_john` | SUCCESS | SOAR_CONTAINMENT_ENGINE | 계정 비활성화 완료. 사유: 비정상 로그인 다수 탐지에 따른 임시 계정 잠금 |
| 2026-10-19T11:48:57.364708 | `block_ip` | `198.51.100.45` | SUCCESS | SOAR_CONTAINMENT_ENGINE | 방화벽 인바운드 차단 규칙 적용 완료 (Drop all). 사유: 해외 미인가 IP 공격 원천 즉각 차단 |
| 2026-10-19T11:48:57.371075 | `terminate_session` | `user_john (Session: sess_9988_token)` | SUCCESS | SOAR_CONTAINMENT_ENGINE | 세션 토큰 폐기 및 Redis 캐시 세션 무효화 완료. 사유: 침해 위험 계정 활성 토큰 무효화 |
| 2026-10-19T11:49:16.795674 | `lock_account` | `user_john` | SUCCESS | SOAR_CONTAINMENT_ENGINE | 계정 비활성화 완료. 사유: 비정상 로그인 다수 탐지에 따른 임시 계정 잠금 |
| 2026-10-19T11:49:16.811365 | `block_ip` | `198.51.100.45` | SUCCESS | SOAR_CONTAINMENT_ENGINE | 방화벽 인바운드 차단 규칙 적용 완료 (Drop all). 사유: 해외 미인가 IP 공격 원천 즉각 차단 |
| 2026-10-19T11:49:16.817452 | `terminate_session` | `user_john (Session: sess_9988_token)` | SUCCESS | SOAR_CONTAINMENT_ENGINE | 세션 토큰 폐기 및 Redis 캐시 세션 무효화 완료. 사유: 침해 위험 계정 활성 토큰 무효화 |

---

## 3. ITSM 티켓 및 에스컬레이션 현황 (Day 3 연동 데이터)
- **발행 티켓 ID**: `SEC-20261019-D25545`
- **티켓 상태**: `ESCALATED`
- **현재 담당 엔지니어**: `secops_lead@company.internal`
- **티켓 제목**: [HIGH] abnormal_login 침해 경보 - user_john

### 티켓 처리 워크로그 및 SLA 추적
- **[2026-10-19T11:49:16.824397]** `SOAR_BOT`: 플레이북에 의한 자동 티켓 생성 및 조치 내역 첨부 완료
- **[2026-10-19T11:49:16.824553]** `ESCALATION_ENGINE`: [SLA 에스컬레이션 발동] Tier-1 (Tier-1 SOC Security Analyst) 경과시간 20분 > SLA 15분. 사유: 야간 교대시간 1차 SOC 분석가 20분간 티켓 무응답. 담당자를 Tier-2 (SecOps Team Lead: secops_lead@company.internal)로 이관합니다.

---

## 4. 침해 지표 (IoC) 및 방화벽 룰 현황
```json
{
  "indicators_of_compromise": [
    {"type": "ipv4", "value": "198.51.100.45", "action": "BLOCKED_ON_PERIMETER_FIREWALL"},
    {"type": "account", "value": "user_john", "status": "LOCKED_OR_ISOLATED"}
  ]
}
```

## 5. 기술팀 후속 조치 과제
1. 호스트 포렌식 아티팩트(Prefetch, Event Log 4624/4625) 정밀 추출
2. 내부망 측면이동(Lateral Movement) 흔적 SIEM 상관분석 쿼리 수행
3. 외부 통신 악성 C2 도메인 DNS Sinkhole 등록 확인
