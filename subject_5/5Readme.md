# SOAR 자동 대응 실습 종합 안내서 (5Readme)

본 문서는 **Day 1 ~ Day 4 바이브코딩 실습(초동대응 리포트 · 승인게이트 · 오탐대응 절차 구현)**의 구현 내역, 임의 설정 데이터 명세, 모듈별 코드 역할, 그리고 파이프라인 실행에 따른 최종 산출 데이터 결과를 상세히 정리한 문서입니다.

---

## 1. 실습 데이터 임의 설정 내역 (데이터는 어떻게 설정했는가)

실습 환경은 실제 SIEM/SOAR 및 기업 보안 인프라(Firewall, WAF, IdP, ITSM)의 동작을 모사하기 위해 다음과 같이 현실적인 모의 데이터를 임의 구성하였습니다.

### 1) 인시던트 모의 데이터 (Day 1)
- **인시던트 ID**: `INC-20261019-001`
- **탐지 이벤트 유형**: `abnormal_login` (비정상 로그인 탐지)
- **위협 수준(Severity)**: `HIGH`
- **공격 유입 출발지 IP**: `198.51.100.45` (러시아 연방 소재 공격자 C2/프록시 모의 IP)
- **공격 대상 계정**: `user_john` (일반 임직원 계정)
- **탐지 상세 내용**: "동일 계정에 대해 해외 미인가 IP에서 5분간 12회 패스워드 인증 실패 후 로그인 성공(Credential Stuffing 의심)"
- **연계 상태 전이**: `NEW` → `ANALYZING` → `APPROVAL_PENDING` → `CONTAINMENT` → `CLOSED`

### 2) 보호 대상 VIP 계정 데이터 (`config/vip_accounts.json`)
비즈니스 연속성 보장 및 임원진/핵심 서비스 계정의 임의 잠금 방지를 위해 정의:
- `ceo_kim` (대표이사 / 경영 총괄): 자동 잠금 원천 금지, CISO/유선 사전 승인 필수
- `cto_lee` (최고기술책임자 / 인프라 마스터): 오잠금 시 빌드/배포 전면 중단 방지
- `ciso_park` (정보보호최고책임자): 최종 보안 결재권자
- `core_service_admin` (대외 결제 연동 서비스 데몬 계정): 결제 장애 방지

### 3) SLA 에스컬레이션 룰 데이터 (`config/escalation_rules.json`)
- **Tier 1 (SOC 1차 보안분석가)**: SLA 15분 이내 초동 분석. 담당자 `analyst_on_duty@company.internal`, 채널 `#soc-incident-alerts`
- **Tier 2 (SecOps 보안팀장)**: SLA 30분 이내 승인 및 격리 통제. 담당자 `secops_lead@company.internal`, 채널 `#soc-lead-escalation`
- **Tier 3 (CISO / 비상대책위)**: SLA 60분. 긴급 전쟁방(`#exec-security-warroom`)

### 4) 조치 유형별 위험등급 데이터 (`config/risk_levels.json`)
- `terminate_session`: **LOW** (위험도 낮음, 자동 승인 및 즉시 실행)
- `block_ip`: **HIGH** (위험도 높음, 방화벽 IP 차단 영향도 사전 검토 및 승인자 필수)
- `lock_account`: **CRITICAL** (위험도 최고, 업무 마비 가능성으로 관리자/CISO 승인 필수)
- `unlock_account`, `unblock_ip`: **LOW** (복구 조치, 해제 사유 필수 기재 조건)

### 5) 오탐(False Positive) 시뮬레이션 데이터
- **인시던트 ID**: `INC-20261019-009-FP`
- **대상 계정/IP**: `marketing_staff` / `115.68.22.10`
- **오탐 사유**: "마케팅팀 임직원 해외 출장 중 공항 무료 Wi-Fi에서 SSL-VPN 접속 시 발생한 정상 MFA 인증 건"

---

## 2. 파일별 코드 구현 내역 (어느 파일에 뭘 하는 코드가 들어갔는가)

`subject_5/` 디렉토리는 Day 1부터 Day 4까지의 요구사항을 모듈형으로 완벽히 분리 구현하였습니다.

```
subject_5/
├── 5Readme                     # [본 파일] 실습 세부사항 종합 설명서
├── main.py                     # Day 1 ~ Day 4 전체 워크플로우 자동 실행 스크립트
├── config/
│   ├── playbook_registry.json  # 이벤트 유형별 플레이북 매핑 레지스트리
│   ├── vip_accounts.json       # VIP 계정 및 보호 예외 정책 설정
│   ├── escalation_rules.json   # 3단계 SLA 및 에스컬레이션 체인 정책
│   └── risk_levels.json        # 조치 유형별 위험도(Low/High/Critical) 및 승인 게이트 규칙
├── playbooks/
│   ├── playbook_abnormal_login.md      # 시나리오 1: 비정상 로그인 플레이북 (트리거/조건/액션/승인자)
│   ├── playbook_traffic_spike.md       # 시나리오 2: 트래픽 급증 및 DDoS 의심 플레이북
│   └── playbook_correlation_attack.md  # 시나리오 3: SIEM 복합 침해 상관분석 플레이북
├── soar/
│   ├── incident.py             # [Day 1] 인시던트 데이터 클래스, 수명주기 상태 전이, 플레이북 매칭
│   ├── containment.py          # [Day 2] 계정잠금, 세션종료, IP차단, VIP 예외처리, 조치 로그(JSON) 누적
│   ├── ticketing.py            # [Day 3] 모의 ITSM 티켓 발급, 2일차 조치내역 본문 자동 연동
│   ├── escalation.py           # [Day 3] SLA 초과 감지 시 담당자 승격(Tier1->Tier2) 및 알림 전파
│   ├── approval_gate.py        # [Day 4] execute_action() 공통 승인 게이트, handle_false_positive() 오탐 복구
│   ├── report.py               # [Day 4] 1~3일차 데이터 자동 취합, 기술팀용/경영진용 2종 리포트 생성
│   ├── containment_log.json    # 격리 조치 및 해제 이력 불변 저장소
│   ├── day03_test_result.md    # Day 3 에스컬레이션 검증 리포트
│   ├── incident_report_tech.md # Day 4 기술팀용 상세 초동대응 리포트 (Markdown)
│   ├── incident_report_exec.md # Day 4 경영진 보고용 요약 리포트 (Markdown)
│   ├── risk_assessment.md      # Day 4 운영 리스크 평가표
│   └── false_positive_dataset.json # Day 4 오탐 데이터셋 (4과목 AI/ML 모델 재학습용)
└── tests/
    └── test_all_scenarios.py   # 전체 파이프라인 자동화 단위 테스트
```

### 세부 모듈 구현 코드 설명:
1. **`soar/incident.py` (Day 1)**:
   - `Incident` 클래스: 고유 ID, 이벤트 유형, 심각도, 출발지 IP, 대상 계정, 원시 로그, 상태 히스토리를 캡슐화.
   - `update_status()`: 인시던트 수명주기 전이 시 타임스탬프, 변경자, 코멘트를 히스토리에 누적.
   - `match_playbook()`: `config/playbook_registry.json`을 조회하여 적절한 대응 지침을 자동 반환.

2. **`soar/containment.py` (Day 2)**:
   - `lock_account()`: 일반 계정은 비활성화하고, VIP 계정은 `VIPAccountException`을 발생시켜 자동 잠금을 차단하고 승인 게이트로 유도.
   - `block_ip()`: 공격 원천 IP 방화벽 차단 모의 실행.
   - `terminate_session()`: 대상 계정의 활성 세션 토큰 강제 만료.
   - `unlock_account()`, `unblock_ip()`: 차단 해제 함수로 해제 사유(`reason`)가 누락되면 `MissingReasonException` 발생.
   - `log_action()`: 모든 조치 행위를 `soar/containment_log.json`에 타임스탬프와 함께 일관되게 기록.

3. **`soar/ticketing.py` & `soar/escalation.py` (Day 3)**:
   - `create_ticket()`: 모의 Jira/ITSM API로, 2일차 `containment_log.json`의 조치 내역을 티켓 본문에 자동으로 첨부하여 발급.
   - `escalate()`: 1차 분석가가 SLA(15분) 내 무응답 시 경과 시간을 감지하고 Tier-2(보안팀장)로 담당자를 변경하며 긴급 알림 전송.
   - `day03_test_result.md`: 에스컬레이션 흐름 시뮬레이션 결과를 문서로 자동 저장.

4. **`soar/approval_gate.py` (Day 4)**:
   - `execute_action()`: 공통 게이트 함수로, `config/risk_levels.json`을 참조하여 `Low` 등급은 즉시 실행, `High`/`Critical` 등급은 승인자(`approver`)가 없는 경우 `APPROVAL_PENDING`을 반환하며 무단 실행 방지.
   - `handle_false_positive()`: 오탐 판정 시 ① 계정/IP 즉시 롤백 해제, ② 복구 원인 로그 기록, ③ 4과목 AI 탐지 모델 재학습용 라벨 데이터(`false_positive_dataset.json`) 생성을 일괄 자동 처리.

5. **`soar/report.py` (Day 4)**:
   - `collect_incident_data()`: 1일차 인시던트 메타데이터, 2일차 격리 조치 이력, 3일차 티켓 및 에스컬레이션 상태를 취합.
   - `generate_technical_report()`: 상세 IoC, 상태 전이 이력, 기술 조치 테이블을 포함한 기술팀용 상세 마크다운 보고서 생성.
   - `generate_executive_report()`: 비즈니스 영향도, 비용 및 고객 영향 요약, 재발방지 권고사항을 담은 경영진용 보고서 생성.

---

## 3. 실행 결과 및 최종 산출 데이터 (최종 데이터는 이렇게 나온다)

`python subject_5/main.py` 실행 시 생성되는 최종 산출물 데이터의 실제 결과입니다.

### 1) 격리 조치 누적 로그 (`soar/containment_log.json`)
조치 일시, 조치 유형, 대상, 처리 상태, 수행자, 상세 사유가 완벽히 보존됩니다:
```json
[
  {
    "timestamp": "2026-10-19T11:49:15.820123",
    "action_type": "lock_account",
    "target": "user_john",
    "status": "SUCCESS",
    "details": "계정 비활성화 완료. 사유: 비정상 로그인 다수 탐지에 따른 임시 계정 잠금",
    "operator": "SOAR_CONTAINMENT_ENGINE"
  },
  {
    "timestamp": "2026-10-19T11:49:15.822145",
    "action_type": "lock_account",
    "target": "ceo_kim",
    "status": "BYPASS_APPROVAL_REQUIRED",
    "details": "VIP 계정(Chief Executive Officer) 자동 잠금 거부됨: 경영 업무 마비 방지 및 고위 임원 사전 유선 승인 필수. 사전 승인 필요",
    "operator": "SOAR_CONTAINMENT_ENGINE"
  },
  {
    "timestamp": "2026-10-19T11:49:15.824200",
    "action_type": "block_ip",
    "target": "198.51.100.45",
    "status": "SUCCESS",
    "details": "방화벽 인바운드 차단 규칙 적용 완료 (Drop all). 사유: 해외 미인가 IP 공격 원천 즉각 차단",
    "operator": "SOAR_CONTAINMENT_ENGINE"
  }
]
```

### 2) 기술팀용 상세 초동대응 리포트 (`soar/incident_report_tech.md`)
- 인시던트 수명주기 전이 이력 (`NEW` -> `ANALYZING` -> `CONTAINMENT`)
- 2일차 격리 조치 내역 테이블 자동 생성
- 3일차 ITSM 티켓(`SEC-20261019-D25545`) 및 에스컬레이션 워크로그 연동
- IoC(침해 지표) JSON 블록 및 기술적 후속 조치 지침 수록

### 3) 경영진 보고용 요약 리포트 (`soar/incident_report_exec.md`)
- 위협 등급 (`HIGH`), 대상 계정, 비즈니스 영향도 분석(초동 차단으로 업무 마비 및 데이터 유출 없음 판정)
- 경영 요약(Executive Summary), 거버넌스 승인 준수 현황, 4과목 AI 파이프라인 지속 투자 권고사항 수록

### 4) 오탐 복구 및 AI 학습용 데이터셋 (`soar/false_positive_dataset.json`)
오탐 시나리오 실행 시 자동으로 추가된 4과목 지도학습 정답 라벨 데이터:
```json
[
  {
    "event_id": "INC-20261019-009-FP",
    "timestamp": "2026-10-19T11:49:15.845012",
    "ground_truth_label": "FALSE_POSITIVE",
    "verified_by": "SECOPS_ANALYST_KANG",
    "reason": "임직원 해외 출장 중 공항 와이파이 VPN 접속에 따른 오경보 확인",
    "features": {
      "source_ip": "115.68.22.10",
      "target_account": "marketing_staff",
      "raw_event_summary": {
        "vpn_type": "SSL-VPN",
        "mfa_success": true
      }
    },
    "ml_feedback": "해당 패턴은 정상 행위로 피드백 가중치 조정 필요 (Retrain Target)"
  }
]
```

### 5) 운영 리스크 평가표 (`soar/risk_assessment.md`)
- 세션 종료(Low), IP 차단(High), 계정 잠금(Critical), VIP 우회 보호, 차단 해제 사유 필수 정책에 대한 완화 통제 장치 및 비즈니스 영향 분석 매트릭스 수록.

---

## 4. 실습 실행 및 검증 방법

언제든지 아래 명령어로 실습 파이프라인과 테스트를 직접 재실행할 수 있습니다.

```powershell
# 1. 전체 SOAR 워크플로우(Day 1 ~ Day 4) 시뮬레이션 실행 및 산출물 갱신
python subject_5/main.py

# 2. 전체 단위 테스트 및 시나리오 검증 실행 (5/5 PASS)
python subject_5/tests/test_all_scenarios.py
```
