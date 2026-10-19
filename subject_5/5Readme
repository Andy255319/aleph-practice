# SOAR 자동 대응 실습 종합 안내서 (5Readme)

본 문서는 **5과목 바이브코딩 실습(플레이북 템플릿 설계 · 계정잠금·접근차단 자동화 · 티켓생성·알림·에스컬레이션 워크플로우)**의 강의 슬라이드 명세와 정확한 설정값/함수 규격을 반영하여 재구성한 코드 내역, 데이터 설정 명세, 테스트 시나리오 실행 결과, 최종 산출 데이터 결과를 정리한 문서입니다.

---

## 1. 5과목 실습 데이터 설정 명세 (슬라이드 규격 반영)

강의 슬라이드에 명시된 데이터 규격 및 설정 파일을 엄밀히 적용하였습니다.

### 1) 플레이북 레지스트리 설정 (`config/playbook_registry.json` - Day 1)
슬라이드 5단계 규격에 따라 이벤트 유형과 대응 수준을 등록:
```json
{
  "playbooks": [
    {
      "id": "PB-LOGIN-001",
      "event_type": "ABNORMAL_LOGIN",
      "response_level": "승인 후 조치"
    },
    {
      "id": "PB-TRAFFIC-001",
      "event_type": "TRAFFIC_SPIKE",
      "response_level": "즉시 자동조치"
    },
    {
      "id": "PB-CORRELATION-001",
      "event_type": "CORRELATED_ATTACK",
      "response_level": "승인 후 조치"
    }
  ]
}
```

### 2) 인시던트 데이터 구조 (`soar_response/incident.py` - Day 1)
슬라이드 4단계의 표준 딕셔너리 스키마 준수:
```python
incident = {
    "event_id": "evt-2001",
    "status": "triaged",
    "history": [
        {
            "status": "detected",
            "message": "비정상 로그인 탐지"
        },
        {
            "status": "triaged",
            "message": "위험도 분석 및 분류 완료"
        }
    ]
}
```

### 3) VIP 계정 설정 (`config/vip_accounts.json` - Day 2)
슬라이드 명세에 따라 VIP 계정 목록을 배열 형태로 관리합니다:
```json
{
  "vip_accounts": [
    "kim",
    "park"
  ]
}
```
- 대상 계정: `kim`, `park`
- 동작 규칙: VIP 계정에 대한 잠금 요청 시 자동 잠금을 수행하지 않고 `APPROVAL_REQUIRED` 결과를 로그에 기록한 뒤 `VIPApprovalRequired` 예외를 발생시켜 승인 절차를 강제합니다.

### 4) SLA 및 에스컬레이션 설정 (`config/escalation_rules.json` - Day 3)
슬라이드 예시 설정을 그대로 반영하였습니다:
```json
{
  "sla_minutes": 10,
  "enabled": true,
  "escalation_chain": [
    "security_analyst",
    "security_manager"
  ]
}
```
- `sla_minutes`: 10 (1차 담당자 SLA 제한 시간 10분)
- `enabled`: true (에스컬레이션 엔진 활성화)
- `escalation_chain`: 1차 담당자 `security_analyst`, 2차 담당자 `security_manager`

### 5) 인시던트 및 테스트 대상 데이터
- **일반 계정**: `lee` (비정상 로그인 반복 공격 대상)
- **VIP 계정**: `kim` (계정 탈취 의심 대상)
- **공격 인입 IP**: `203.0.113.25` (비정상 로그인 공격 원천)
- **보안 이벤트 ID**: `evt-2001` (또는 `INC-20261019-001`)

---

## 2. 파일별 구현 코드 내역 (어느 파일에 뭘 하는 코드가 들어갔는가)

슬라이드에서 요구한 정확한 파일 경로, 함수명, 매개변수, 예외 클래스를 구현하였습니다.

### 1) 플레이북 문서 템플릿 (`soar_response/playbooks/` & `playbooks/` - Day 1)
공통 템플릿(플레이북 ID, 플레이북 이름, 트리거, 조건, 액션, 승인자, 예상 소요 시간)을 준수하여 3대 대표 시나리오를 작성:
- **`PB-LOGIN-001.md` (시나리오 A. 비정상 로그인)**:
  - 트리거: 짧은 시간에 로그인 실패 반복 발생 후 로그인 성공
  - 조건: 동일 사용자·IP·시간대 연관성 확인 및 위험도 평가
  - 액션: 로그 수집 $\rightarrow$ 담당자 알림 $\rightarrow$ 계정 잠금 검토
  - 승인: 보안 담당자 사전 승인 후 실행 (예상 소요 시간: 5분)
- **`PB-TRAFFIC-001.md` (시나리오 B. 트래픽 급증)**:
  - 트리거: 현재 트래픽이 기준선보다 급격히 증가
  - 조건: 정상 트래픽 증가인지, 특정 출발지 집중 요청인지 확인
  - 액션: 트래픽 분석 $\rightarrow$ 운영 담당자 알림 $\rightarrow$ 제한 조치 검토
  - 승인: 서비스 영향 차단·제한 조치는 담당자 승인 후 실행 (예상 소요 시간: 3분)
- **`PB-CORRELATION-001.md` (시나리오 C. 상관분석 매칭)**:
  - 트리거: 로그인 실패 급증 $\rightarrow$ 로그인 성공 $\rightarrow$ 비인가 접근 연관 패턴 탐지
  - 조건: 사용자, IP, 시간 순서 및 접근 권한 확인
  - 액션: 관련 이벤트 통합 $\rightarrow$ 위험도 평가 $\rightarrow$ 담당자 알림 $\rightarrow$ 계정 조치 검토
  - 승인: 계정 비활성화 등 영향 큰 조치는 승인 후 실행 (예상 소요 시간: 10분)

### 2) `soar_response/incident.py` & `soar/incident.py` (Day 1 상태 전이 및 자동 매칭)
- **`update_status(incident, new_status, message)`**:
  - incident의 현재 status를 변경.
  - 변경된 상태와 처리 내용을 history에 추가.
  - 콘솔에 처리 이력을 출력(`[상태 전이 확인] ...`)하여 상태 변경이 정상적으로 이루어졌는지 확인.
- **`match_playbook(event_type)`**:
  - `config/playbook_registry.json`을 읽어 이벤트 유형에 대응하는 플레이북 반환.

### 3) `soar/containment.py` (Day 2 조치 함수 및 공통 로그 함수)
- **`VIPApprovalRequired(Exception)`**: VIP 계정 잠금 시도 시 발생하는 전용 예외 클래스.
- **`log_action(action, target, result, reason)`**:
  - 조치 이력을 `soar/containment_log.json`에 누적 기록.
  - 결과(`result`): `SUCCESS` (성공), `FAIL` (실패), `SKIPPED` (건너뜀), `APPROVAL_REQUIRED` (승인 필요).
  - 기록 필드: `timestamp`, `action`, `target`, `result`, `reason`.
- **`lock_account(username, reason)`**:
  - 일반 계정 잠금 처리.
  - `kim`, `park` 등 VIP 계정인 경우:
    1. `APPROVAL_REQUIRED` 결과를 `log_action()`으로 기록.
    2. `VIPApprovalRequired` 예외 발생.
    3. 호출부 try/except에서 예외를 처리하고 자동 잠금 대신 승인 필요 메시지 출력.
- **`unlock_account(username, reason)`**:
  - 계정 잠금 해제.
  - 사유가 없거나 공백만 입력된 경우 실행하지 않고 `FAIL` 기록 (`reason: 해제 사유 누락`).
  - 이미 해제되었거나 잠금 상태가 아닌 경우 `SKIPPED` 기록.
- **`block_ip(ip_address, reason)`**: IP 차단 및 성공 이력 기록 (테스트 모드 지원).
- **`unblock_ip(ip_address, reason)`**: IP 차단 해제. 사유 누락 시 `FAIL`, 중복 해제 시 `SKIPPED` 처리.
- **`terminate_session(username, reason)`**: 해당 사용자의 활성 세션 토큰 무효화.

### 4) `soar/ticketing.py` (Day 3 티켓 생성 및 상태 동기화)
- **`create_ticket(incident, action_results)`**:
  - Incident 정보와 조치 결과(2건 이상)를 이용해 티켓 생성.
  - 슬라이드 필수 7대 필드 포함:
    - `ticket_id`: 고유 ID (`TICK-YYYYMMDD-XXXXXX`)
    - `event_id`: 연결된 보안 이벤트 ID (`evt-2001`)
    - `title`: 사건 제목 (`[HIGH] ABNORMAL_LOGIN 대응 요청 - lee`)
    - `status`: 티켓 상태 (초기 `OPEN`)
    - `assignee`: 현재 담당자 (`security_analyst`)
    - `body`: 사건 정보와 조치 결과 2건 모두 본문에 포맷팅
    - `created_at`: 생성 시각 (ISO-8601)
- **`sync_ticket_status(incident, ticket)`**:
  - Incident 수명주기 전이에 따라 티켓 상태를 동기화 (`CONTAINMENT` $\rightarrow$ `IN_PROGRESS`, `CLOSED` $\rightarrow$ `RESOLVED` 등).

### 5) `soar/escalation.py` (Day 3 SLA 알림 및 에스컬레이션)
- **`check_and_escalate(ticket, elapsed_minutes, responded, rules)`**:
  - TC-01 ~ TC-07 시나리오 완벽 지원:
    - SLA 이내 응답 시: 에스컬레이션 미발생
    - SLA 미초과 시: 에스컬레이션 미발생
    - SLA 초과 및 미응답 시: 2차 담당자(`security_manager`)에게 알림 전송 및 `assignee` 갱신
    - 이미 에스컬레이션된 티켓: 중복 알림 방지 (`already_escalated`)
    - 설정 파일의 SLA 변경 시: 변경된 기준 동적 적용

---

## 3. 테스트 시나리오 실행 결과 (최종 데이터는 이렇게 나온다)

### 1) Day 1 플레이북 매칭 및 상태 전이 결과
- **인시던트 생성**: `event_id: evt-2001`, `status: detected`
- **3대 플레이북 매칭 검증**:
  - `ABNORMAL_LOGIN` $\rightarrow$ `PB-LOGIN-001` (대응 수준: 승인 후 조치)
  - `TRAFFIC_SPIKE` $\rightarrow$ `PB-TRAFFIC-001` (대응 수준: 즉시 자동조치)
  - `CORRELATED_ATTACK` $\rightarrow$ `PB-CORRELATION-001` (대응 수준: 승인 후 조치)
- **`update_status()` 검증**:
  - 출력: `[상태 전이 확인] Incident ID: evt-2001 | 상태: detected -> triaged | 내용: 위험도 분석 및 분류 완료`

### 2) Day 2 계정잠금·접근차단 시나리오 결과
- **시나리오 A: 일반 계정 자동 잠금**
  - 입력: 계정 `lee`, 사유 `비정상 로그인 반복`
  - 결과: `result: SUCCESS` | 계정 잠금 처리 및 이력 기록 완료
- **시나리오 B: VIP 계정 승인 필요**
  - 입력: 계정 `kim`, 사유 `계정 탈취 의심`
  - 결과: `VIPApprovalRequired` 예외 발생 $\rightarrow$ 호출부 try/except 처리 $\rightarrow$ 자동 잠금 미실행 및 `result: APPROVAL_REQUIRED` 이력 기록 완료
- **시나리오 C: IP 차단과 세션 종료**
  - 입력: IP `203.0.113.25`, 계정 `lee`, 사유 `악성 IP에서 비정상 로그인 탐지`
  - 결과: IP 차단 `result: SUCCESS`, 활성 세션 종료 `result: SUCCESS` 각각 기록 완료
- **추가 테스트 (해제 및 예외 검증)**:
  - 사유 누락 잠금 해제: `result: FAIL` (해제 사유 누락)
  - 정상 잠금 해제: `result: SUCCESS` (관제 분석 완료 후 정상 복구)
  - 이미 해제된 계정 재해제: `result: SKIPPED` (이미 잠금 해제되었거나 잠금 상태가 아닌 계정)
  - 정상 IP 차단 해제: `result: SUCCESS` (공격 소멸 확인 후 방화벽 롤백)

### 3) Day 3 티켓생성 및 에스컬레이션 시나리오 (TC-01 ~ TC-07) 검증 결과

| 테스트 | 조건 | 예상 결과 | 실제 실행 결과 | 판정 |
|---|---|---|---|---|
| **TC-01** | 정상 Incident 입력 | 티켓 생성 성공 | 티켓 ID 발급 완료 (`TICK-20261019-XXXXXX`) | **PASS** |
| **TC-02** | 조치 결과 2건 입력 | 두 조치 모두 티켓 본문에 반영 | IP 차단 및 세션 종료 2건 모두 본문에 포맷팅 첨부됨 | **PASS** |
| **TC-03** | 1차 담당자가 SLA 이내 응답 | 에스컬레이션 발생 안 함 | `escalated: False` (정상 응답 확인) | **PASS** |
| **TC-04** | 1차 담당자 미응답, SLA 미초과 (8분 $\le$ 10분) | 에스컬레이션 발생 안 함 | `escalated: False` (제한 시간 미초과) | **PASS** |
| **TC-05** | 1차 담당자 미응답, SLA 초과 (15분 > 10분) | 2차 담당자에게 알림 | `escalated: True`, 담당자 $\rightarrow$ `security_manager` 이관 및 알림 발송 | **PASS** |
| **TC-06** | 이미 에스컬레이션된 티켓 재검사 | 중복 알림 방지 | `escalated: False` (`already_escalated: True`, 중복 발송 차단) | **PASS** |
| **TC-07** | 설정 파일의 SLA 변경 (10분 $\rightarrow$ 5분) | 변경된 SLA 기준 적용 | 경과 6분 시 변경된 5분 기준 초과 감지하여 에스컬레이션 발동 | **PASS** |

### 4) 조치 이력 로그 최종 검증 (`soar/containment_log.json`)
슬라이드 최종 검증 항목을 모두 만족합니다:
- [x] 모든 조치 결과가 JSON에 누적되는가?
- [x] 각 기록에 시간(`timestamp`), 조치 유형(`action`), 대상(`target`), 결과(`result`), 사유(`reason`)가 포함되는가?
- [x] 기존 이력이 새로운 실행으로 인해 삭제되지 않고 append 되는가?
- [x] VIP 승인 필요 기록(`APPROVAL_REQUIRED`)과 해제 이력(`SUCCESS`, `FAIL`, `SKIPPED`)도 정상 저장되는가?

```json
[
  {
    "timestamp": "2026-10-19T12:23:38.212000",
    "action": "lock_account",
    "target": "lee",
    "result": "SUCCESS",
    "reason": "비정상 로그인 반복"
  },
  {
    "timestamp": "2026-10-19T12:23:38.213000",
    "action": "lock_account",
    "target": "kim",
    "result": "APPROVAL_REQUIRED",
    "reason": "[VIP 보호] 계정 잠금 사전 승인 필요: 계정 탈취 의심"
  },
  {
    "timestamp": "2026-10-19T12:23:38.218000",
    "action": "block_ip",
    "target": "203.0.113.25",
    "result": "SUCCESS",
    "reason": "악성 IP에서 비정상 로그인 탐지"
  },
  {
    "timestamp": "2026-10-19T12:23:38.225000",
    "action": "terminate_session",
    "target": "lee",
    "result": "SUCCESS",
    "reason": "악성 IP에서 비정상 로그인 탐지"
  },
  {
    "timestamp": "2026-10-19T12:23:38.231000",
    "action": "unlock_account",
    "target": "lee",
    "result": "FAIL",
    "reason": "해제 사유 누락 (사유가 없거나 공백)"
  },
  {
    "timestamp": "2026-10-19T12:23:38.238000",
    "action": "unlock_account",
    "target": "lee",
    "result": "SUCCESS",
    "reason": "관제 분석 완료 후 정상 복구"
  },
  {
    "timestamp": "2026-10-19T12:23:38.244000",
    "action": "unlock_account",
    "target": "lee",
    "result": "SKIPPED",
    "reason": "이미 잠금 해제되었거나 잠금 상태가 아닌 계정"
  }
]
```

---

## 4. 실행 및 검증 방법

```powershell
# 1. 5과목 전체 파이프라인 (Day 1 ~ Day 4 슬라이드 규격 반영) 실행
python subject_5/main.py

# 2. 슬라이드 시나리오 전체 단위 테스트 실행 (7/7 PASS)
python subject_5/tests/test_all_scenarios.py
```
