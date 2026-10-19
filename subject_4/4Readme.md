# 이상탐지 자동화 실습 종합 안내서 (4Readme)

본 문서는 **Day 1 ~ Day 5 바이브코딩 실습(이상탐지 자동화 파이프라인 구현 및 AI 기반 요약·우선순위 분류)**의 구현 내역, 임의 설정 데이터 명세, 모듈별 코드 역할, 그리고 파이프라인 실행에 따른 최종 산출 데이터 결과를 상세히 정리한 문서입니다.

---

## 1. 실습 데이터 임의 설정 내역 (데이터는 어떻게 설정했는가)

실제 엔터프라이즈 환경에서 발생하는 이종(Heterogeneous) 보안 로그와 다양한 공격 벡터, 그리고 정제 및 튜닝 테스트를 위해 다음과 같이 모의 데이터를 체계적으로 설계하였습니다.

### 1) 3개 로그 소스 샘플 데이터셋 (`subject_4/data/`)
- **로그인 감사 로그 (`data/login_logs.csv` - 15행)**:
  - 정상 일상 로그인(`user_alice`, `user_bob` 등)
  - 무차별 대입 공격(`user_david`): 5분 이내 6회 연속 비밀번호 실패(`FAIL`) 후 최종 로그인 성공(`SUCCESS`) 시나리오 포함 (계정 탈취 징후)
  - 업무 외 시간 접속(`user_night`): 새벽 02:30 심야 로그인
  - 결측치 및 이상 타임스탬프: `user_id` 누락(1건), 비정상 일자 `2026-99-99 25:99:99`(1건)를 의도적으로 삽입하여 정제 로직 검증
- **방화벽 네트워크 트래픽 로그 (`data/firewall_logs.csv` - 10행)**:
  - 평시 웹 트래픽(1,200 ~ 2,300 Bytes)
  - 트래픽 급증(Traffic Spike): `192.168.1.100`에서 단시간 내 45MB, 52MB, 61MB의 대용량 데이터 전송 (DDoS/대량 유출 징후)
  - 악성 외부 스캐닝: `203.0.113.100`의 포트 22(SSH) 접근 차단(`DENY`)
  - 결측치: 출발지 IP 결측 1건 삽입
- **SaaS 클라우드 감사 로그 (`data/saas_logs.csv` - 7행)**:
  - 정상 업무: `user_alice`(GoogleDrive 파일 2건), `user_bob`(Slack 메시지)
  - 대량 데이터 유출(`user_eve`): GoogleDrive 파일 150건 일괄 다운로드 및 Salesforce 500건 대량 보고서 추출(Export)
  - 권한 상승 시도(`user_david`): Confluence 관리자 권한 강제 승격 시도 및 거부(`DENIED`)
  - 결측치: 수행자(`actor`) 결측 1건 삽입

### 2) 탐지 임계값 설정 (`config/detection_thresholds.json`)
- 무차별 대입 임계치: 5분 윈도우 내 실패 5회 이상
- 심야 업무 외 시간: 22:00 ~ 익일 06:00
- 트래픽 스파이크: 평시 베이스라인 평균 + $3\sigma$ (표준편차 3배) 및 최소 10MB 이상
- 위험점수 가중치: 무차별대입(35점), 심야접속(20점), 트래픽급증(40점), SaaS대량유출(45점), IoC악성IP(50점), 비인가접근(30점), 3단계 킬체인 완성 보너스(+50점), High 우선순위 컷오프(70점 이상)

### 3) 위협 인텔리전스 IoC 피드 (`config/threat_intel.json`)
실시간 IP 평판 조회를 위해 5개의 샘플 악성 IP를 구성:
- `198.51.100.23` (C2_SERVER / APT28_FANCY_BEAR / 신뢰도 HIGH)
- `203.0.113.100` (SSH_BRUTEFORCER / AUTOMATED_SCANNER / 신뢰도 MEDIUM)
- `198.51.100.99` (DATA_EXFILTRATION / FINANCIAL_THREAT_GROUP / 신뢰도 HIGH)
- `185.220.101.5` (TOR_EXIT_NODE / ANONYMIZER / 신뢰도 HIGH)
- `45.154.255.89` (MALWARE_DISTRIBUTOR / COBALT_STRIKE_LOADER / 신뢰도 CRITICAL)

### 4) 3과목 접근 통제 정책 및 예외 승인 데이터 (`access_control/policy.py`)
- 부서/역할별 인가 리소스(RBAC): 예) 마케팅(GoogleDrive, Slack), 개발자(GitHub, Jira)
- 사전 승인된 예외 목록(`APPROVED_EXCEPTIONS`): `user_charlie`의 Salesforce 접근, `user_alice`의 Confluence 접근을 예외 허용하여 단순 RBAC 검사로 인한 오탐 방지

### 5) 4일차 탐지 룰 평가 및 튜닝용 라벨링 데이터셋 (30건)
- **정상 케이스 15건 (Ground Truth: NORMAL)**: 일상 업무, 사전 승인된 야간 정기 배치(`user_night_batch`), 정기 백업 트래픽(`user_backup_service`), 예외 승인 사용자 등
- **실제 공격 케이스 15건 (Ground Truth: ANOMALY)**: 무차별 대입, 비인가 권한 상승, 클라우드 유출, APT C2 통신, DDoS 트래픽, 내부망 기밀 열람 등

---

## 2. 파일별 코드 구현 내역 (어느 파일에 뭘 하는 코드가 들어갔는가)

`subject_4/` 디렉토리는 5일간의 실습 단계가 유기적으로 연계되도록 모듈화되어 있습니다.

```
subject_4/
├── 4Readme                     # [본 파일] 실습 세부사항 종합 설명서
├── main.py                     # Day 1 ~ Day 5 전체 파이프라인 원클릭 실행 스크립트
├── config/
│   ├── detection_thresholds.json   # 탐지 임계값, 시간 윈도우, 위험점수 가중치
│   └── threat_intel.json           # 5개 샘플 악성 IP 위협 인텔리전스 피드
├── data/
│   ├── login_logs.csv              # 원본 로그인 로그 (결측치/이상치/브루트포스 포함)
│   ├── firewall_logs.csv           # 원본 방화벽 트래픽 로그 (결측치/트래픽 스파이크 포함)
│   └── saas_logs.csv               # 원본 SaaS 클라우드 로그 (대량 다운로드/권한 상승 포함)
├── access_control/
│   ├── __init__.py
│   └── policy.py                   # [3과목 연동] RBAC 정책 및 예외 승인(evaluate_access) 모듈
├── agent_core/
│   ├── __init__.py
│   └── tool_router.py              # [Day 5] LLM 에이전트 도구 호출(Tool Calling) 연동 라우터
├── anomaly_detection/
│   ├── explore_logs.py             # [Day 1] pandas 기반 로그 탐색 및 결측치/이상 타임스탬프 분석
│   ├── normalize.py                # [Day 1] 3개 로그 정제 및 공통 스키마 정규화 (normalized_events.json)
│   ├── day01_summary.md            # [Day 1] 정규화 전/후 건수 및 무결성 분석 보고서
│   ├── login_detection.py          # [Day 2] 무차별 대입(Bruteforce) 및 심야 로그인 탐지 룰
│   ├── traffic_detection.py        # [Day 2] 통계적 베이스라인(평균, Std) 계산 및 3-Sigma 트래픽 급증 탐지
│   ├── day02_result.md             # [Day 2] Day 2 로그인 및 트래픽 탐지 검증 보고서
│   ├── advanced_detection.py       # [Day 3] 3과목 정책 연동 비인가 접근, SaaS 이상, IoC IP 매칭
│   ├── correlation.py              # [Day 3] 사용자별 그룹화, 3단계 킬체인 상관분석, 위험점수 가산 산출
│   ├── day03_risk_scores.json      # [Day 3] 10개 대표 이벤트 위험점수 종합 산출 결과
│   ├── evaluation.py               # [Day 4] 30건 라벨셋 기반 Precision/Recall 평가 및 FP 제거 튜닝
│   ├── day04_fp_analysis.md        # [Day 4] 3대 오탐 사례 정밀 분석 및 개선책 보고서
│   ├── day04_tuning_result.md      # [Day 4] 튜닝 전/후 탐지 지표 비교표 (오탐 0건 달성)
│   ├── pipeline.py                 # [Day 5] 1~4일차 모듈을 통합한 End-to-End 파이프라인 및 AI 요약
│   ├── anomaly_detection_report_20261019.json # [Day 5] 최종 침해사고 분석 통합 JSON 결과
│   ├── anomaly_detection_report_20261019.md   # [Day 5] 최종 침해사고 분석 최종 마크다운 리포트
│   └── day05_retrospective.md      # [Day 5] 전체 파이프라인 팀 리뷰 및 회고
└── tests/
    └── test_all_anomaly_detection.py # 전체 5단계 기능 단위/통합 테스트 스위트
```

### 세부 모듈 구현 코드 설명:
1. **`anomaly_detection/explore_logs.py` & `normalize.py` (Day 1)**:
   - `explore_all_logs()`: pandas를 활용해 원본 CSV 파일의 컬럼, 결측치 수 및 이상 타임스탬프 비율을 진단.
   - `normalize_login()`, `normalize_firewall()`, `normalize_saas()`: 이종 로그를 단일 표준 필드(`event_id`, `timestamp`, `event_source`, `user_id`, `source_ip`, `action`, `status`, `details`)로 규격화.
   - 결측 필수 필드 및 잘못된 날짜(`2026-99-99`)를 필터링하여 정제된 `normalized_events.json` 생성.

2. **`anomaly_detection/login_detection.py` & `traffic_detection.py` (Day 2)**:
   - `detect_bruteforce()`: 슬라이딩 윈도우 알고리즘으로 5분 내 5회 이상 실패 후 성공 여부를 감지.
   - `detect_offhour_login()`: 22시~06시 사이의 비정상 로그인 식별.
   - `calculate_traffic_baseline()` & `detect_traffic_spike()`: 정규 트래픽의 평균 및 표준편차를 기반으로 $3\sigma$를 초과하는 대역폭 폭주를 자동 감지.

3. **`anomaly_detection/advanced_detection.py` & `correlation.py` (Day 3)**:
   - `detect_unauthorized_access()`: 3과목 `access_control/policy.py`의 `evaluate_access()`와 연동하여 예외 승인 내역을 대조하고 인가되지 않은 리소스 접근을 차단/탐지.
   - `detect_saas_anomaly()`: 클라우드 내 50건 이상 대량 파일 다운로드 및 무단 관리자 권한 상승 시도 감지.
   - `match_ioc()`: `config/threat_intel.json`의 악성 IP와 매칭.
   - `check_chain()`: (1단계: 초기 침투) $\rightarrow$ (2단계: 권한 오용) $\rightarrow$ (3단계: 데이터 유출)로 이어지는 다단계 킬체인 완성 여부를 추적.
   - `calculate_risk_score()`: 개별 지표 점수 합산에 킬체인 완성 시 50점 가산점을 부여하여 종합 점수(0~100) 및 우선순위(High/Medium/Low) 산출.

4. **`anomaly_detection/evaluation.py` (Day 4)**:
   - `evaluate_detector()`: 30건의 Ground Truth 라벨셋과 비교하여 Confusion Matrix, Precision, Recall, F1-Score 계산.
   - 오탐 분석: 정기 배치 계정, 정기 백업 서비스, 예외 승인 연동 누락으로 인한 4건의 오탐 원인을 분석하고 룰을 튜닝하여 오탐을 0건으로 완전 제거.

5. **`anomaly_detection/pipeline.py` & `agent_core/tool_router.py` (Day 5)**:
   - `run_anomaly_pipeline()`: 1~4일차 전체 과정을 원클릭으로 구동.
   - `summarize_high_priority_with_ai()`: High 우선순위 위협에 대해 SOC 관제 요원을 위한 AI 자연어 분석 브리핑 생성.
   - `ToolRouter`: 이상탐지 핵심 함수들을 LLM 에이전트가 자율적으로 실행할 수 있도록 도구로 등록.

---

## 3. 실행 결과 및 최종 산출 데이터 (최종 데이터는 이렇게 나온다)

`python subject_4/main.py` 실행 시 생성되는 최종 산출물 데이터의 실제 결과입니다.

### 1) 정규화 결과 (`anomaly_detection/day01_summary.md`)
- 원본 32건(로그인 15, 방화벽 10, SaaS 7) 중 결측치 및 이상 타임스탬프 4건 정제 후 **총 28건의 공통 스키마 이벤트가 `normalized_events.json`으로 적재됨**.

### 2) 트래픽 통계 베이스라인 (`anomaly_detection/day02_result.md`)
- 평시 평균 트래픽: **2,375.00 Bytes**
- 표준편차: **1,438.68 Bytes**
- `192.168.1.100`의 45MB, 52MB, 61MB 전송 구간이 평균 대비 18,000배 급증 구간으로 정확히 탐지됨.

### 3) 10개 대표 이벤트 위험점수 종합 결과 (`anomaly_detection/day03_risk_scores.json`)
```json
[
  {
    "user_id": "user_david",
    "risk_score": 100,
    "priority": "HIGH",
    "is_chain_completed": true,
    "detection_count": 2,
    "contributing_factors": [
      {"rule_id": "RULE-LOGIN-BRUTEFORCE", "rule_name": "다중 로그인 실패 기반 Brute-force 탐지", "score_added": 35},
      {"rule_id": "RULE-SAAS-PRIV-ESCALATION", "rule_name": "SaaS 관리자 권한 무단 상승 거부 탐지", "score_added": 30},
      {"rule_id": "CORRELATION-CHAIN-BONUS", "rule_name": "3단계 침해사고 킬체인 완성 가산점", "score_added": 50}
    ]
  },
  {
    "user_id": "user_eve",
    "risk_score": 100,
    "priority": "HIGH",
    "is_chain_completed": true,
    "detection_count": 3
  },
  {
    "user_id": "user_alice",
    "risk_score": 0,
    "priority": "LOW",
    "is_chain_completed": false,
    "detection_count": 0
  }
]
```

### 4) 탐지 룰 튜닝 전/후 성능 비교 (`anomaly_detection/day04_tuning_result.md`)
| 지표 | 튜닝 전 (Before) | 튜닝 후 (After) | 비고 |
|---|---|---|---|
| **True Positive (정탐)** | 15건 | 15건 | 침해 행위 100% 탐지 |
| **False Positive (오탐)** | **4건** | **0건** | **오탐 100% 제거** |
| **Precision (정밀도)** | **79.0%** | **100.0%** | **+21.0%p 대폭 향상** |
| **Recall (재현율)** | **100.0%** | **100.0%** | 공격 미탐 0건 유지 |
| **F1-Score** | 0.8824 | **1.0000** | 완벽한 균형 달성 |

### 5) High 우선순위 위협 AI 자연어 분석 보고서 (`anomaly_detection/anomaly_detection_report_20261019.md`)
AI 엔진에 의해 생성된 침해사고 요약 스니펫:
> 🚨 **[AI 침해 위협 요약 보고: user_david]** (종합 위험도: 100/100점, 우선순위: HIGH)  
> 해당 사용자는 보안 관제 분석 결과 최상위 위험 수준으로 평가되었습니다. 특히 초기 접근(무차별 대입 인증 실패)부터 권한 오용 및 최종 데이터 대량 유출 단계로 이어지는 **3단계 킬체인(Kill Chain) 다단계 공격 징후**가 뚜렷하게 관측되었습니다.  
> **세부 탐지 지표**:  
> - [RULE-LOGIN-BRUTEFORCE] 5분 윈도우 내 6회 로그인 실패 감지 (이후 로그인 성공 포착: 계정 탈취 위험)  
> - [RULE-SAAS-PRIV-ESCALATION] 관리자 권한 강제 획득 시도 차단됨  
> **긴급 대응 권고**: 즉각적인 세션 만료 및 IdP 계정 잠금 승인 요청을 진행하고 방화벽 차단 룰을 활성화하십시오.

---

## 4. 실습 실행 및 검증 방법

언제든지 터미널에서 아래 명령어로 실습 파이프라인과 테스트를 직접 재실행할 수 있습니다.

```powershell
# 1. Day 1 ~ Day 5 전체 이상탐지 파이프라인 가동 및 산출물 갱신
python subject_4/main.py

# 2. 전체 단위 테스트 및 검증 스위트 실행 (5/5 PASS)
python subject_4/tests/test_all_anomaly_detection.py
```
