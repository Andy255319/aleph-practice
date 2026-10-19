# [4과목] 이상탐지 자동화 실습 종합 안내서 (4Readme)

본 문서는 **Day 1 ~ Day 5 바이브코딩 실습(이상탐지 자동화 파이프라인 구현 및 AI 기반 요약·우선순위 분류)**의 구현 내역, 실습 교재 원본 데이터셋 명세, 6대 핵심 탐지 함수 및 상관분석 설계, 그리고 파이프라인 실행에 따른 산출물을 종합 정리한 문서입니다.

---

## 1. 실습 데이터셋 명세 (Day 1 실습 교재 원본 데이터)

실습 교재(`DAY 1 · 바이브코딩 실습: 샘플 로그 데이터셋 탐색 및 전처리`) 규격을 100% 반영하여 결측치, 이상 타임스탬프, 슬래시/대시 혼용 포맷을 갖춘 원본 CSV 파일들을 `subject_4/data/`에 구성하였습니다.

### 1) 로그인 감사 로그 (`data/login_logs_practice.csv` / `login_logs.csv` - 10행)
```csv
timestamp,user,src_ip,result
2026-10-05 08:55:12,kim,192.168.110.21,SUCCESS
2026-10-05 09:01:03,lee,192.168.110.22,FAIL
2026-10-05 09:01:08,lee,192.168.110.22,FAIL
2026-10-05 09:01:15,lee,192.168.110.22,SUCCESS
2026-10-05 09:15:44,park,192.168.110.23,SUCCESS
2026/10/05 09:20:11,choi,192.168.110.24,SUCCESS
not-a-time,kim,192.168.110.21,FAIL
2026-10-05 10:05:32,,192.168.110.25,FAIL
2026-10-05 10:06:01,kim,,FAIL
2026-10-05 23:48:02,choi,192.168.110.24,SUCCESS
```
- **데이터 특징 및 이상 징후**:
  - `lee` (192.168.110.22): 09:01:03 및 09:01:08 연속 2회 실패(`FAIL`) 후 09:01:15 로그인 성공(`SUCCESS`) 포착 (무차별 대입 후 계정 탈취 징후)
  - `choi` (192.168.110.24): 23:48:02 심야 업무 외 시간 로그인 성공
  - 결측치/이상치 정제: `not-a-time` 비정상 타임스탬프 1건, `user` 결측 1건, `src_ip` 결측 1건 필터링
  - 포맷 정규화: `2026/10/05 09:20:11` 슬래시 포맷을 ISO-8601(`2026-10-05T09:20:11`)로 자동 변환

### 2) 방화벽 네트워크 트래픽 로그 (`data/firewall_logs_practice.csv` / `firewall_logs.csv` - 10행)
```csv
timestamp,src_ip,dst_ip,dst_port,protocol,action
2026-10-05 08:58:10,192.168.110.21,10.0.0.10,443,TCP,ALLOW
2026-10-05 09:03:22,192.168.110.22,10.0.0.20,443,TCP,ALLOW
2026-10-05 09:04:10,192.168.110.22,10.0.0.30,22,TCP,DENY
2026-10-05 09:04:15,192.168.110.22,10.0.0.31,22,TCP,DENY
2026-10-05 09:10:05,192.168.110.23,10.0.0.10,53,UDP,ALLOW
2026/10/05 09:12:40,192.168.110.24,10.0.0.10,53,UDP,ALLOW
not-a-time,192.168.110.25,10.0.0.40,3389,TCP,DENY
2026-10-05 10:01:33,,10.0.0.10,443,TCP,ALLOW
2026-10-05 10:05:18,192.168.110.21,,80,TCP,ALLOW
2026-10-05 22:55:09,192.168.110.24,10.0.0.60,445,TCP,DENY
```
- **데이터 특징 및 이상 징후**:
  - `192.168.110.22` (`lee`): 09:04 시점에 SSH 포트 22(10.0.0.30, 10.0.0.31)로 5초 간격 연속 스캔 시도 및 차단(`DENY`) 포착 (비인가 내부망 정찰)
  - `192.168.110.24` (`choi`): 22:55:09 심야에 445번 포트(SMB) 접근 시도 및 차단(`DENY`)
  - 결측치/이상치 정제: `not-a-time` 1건, `src_ip` 결측 1건, `dst_ip` 결측 1건 필터링

### 3) SaaS 애플리케이션 감사 로그 (`data/saas_logs_practice.csv` / `saas_logs.csv` - 10행)
```csv
timestamp,user,service,action,src_ip,result
2026-10-05 09:05:11,kim,drive,LOGIN,192.168.110.21,SUCCESS
2026-10-05 09:07:32,lee,slack,LOGIN,192.168.110.22,SUCCESS
2026-10-05 09:15:03,park,drive,UPLOAD,192.168.110.23,SUCCESS
2026-10-05 09:20:14,choi,mail,LOGIN,192.168.110.24,SUCCESS
2026-10-05 09:35:44,kim,drive,DOWNLOAD,192.168.110.21,SUCCESS
2026-10-05 09:36:01,kim,drive,DOWNLOAD,192.168.110.21,SUCCESS
2026/10/05 10:02:41,lee,jira,LOGIN,192.168.110.22,SUCCESS
not-a-time,park,drive,DOWNLOAD,192.168.110.23,SUCCESS
2026-10-05 10:15:22,,drive,DOWNLOAD,192.168.110.25,SUCCESS
2026-10-05 23:40:05,lee,drive,DOWNLOAD,192.168.110.22,SUCCESS
```
- **데이터 특징 및 이상 징후**:
  - `lee`: 평소 개발팀 업무로 `slack`, `jira`만 사용하다가, 심야 23:40:05에 평소 사용하지 않던 `drive`에 접속하여 중요 파일 `DOWNLOAD` 수행 (사용자별 정상 기준선 이탈 및 심야 데이터 유출 의심)
  - `kim`: 09:35:44 및 09:36:01 불과 17초 사이에 드라이브에서 2회 연속 급속 다운로드 수행 (다운로드 빈도 임계치 초과)
  - 결측치/이상치 정제: `not-a-time` 1건, `user` 결측 1건 필터링

---

## 2. 탐지 함수 및 상관분석 설계 (Day 4 실습 교재 슬라이드 규격)

실습 교재(`DAY 4 · 바이브코딩 실습: 기존 탐지룰 튜닝(오탐 감소)`)의 핵심 요구사항 표를 코드로 구현하였습니다.

| 탐지 함수 | 필요한 입력 | 평가 시 고려할 점 | 구현 모듈 및 로직 |
| :--- | :--- | :--- | :--- |
| **`detect_bruteforce()`** | 사용자별 로그인 로그와 시간 범위 | **단일 로그 한 건만으로 판단하기 어려움** | `anomaly_detection/login_detection.py`<br>- 사용자별 로그인 로그를 분리하고 5분 윈도우 내 연속 실패 카운트 집계<br>- 실패 직후 로그인 성공 여부(계정 탈취)를 판정하여 가중치 부여 |
| **`detect_offhour_login()`** | 로그인 로그 한 건 | **개별 이벤트 평가 가능** | `anomaly_detection/login_detection.py`<br>- 단일 로그의 타임스탬프가 심야(22:00 ~ 06:00)인지 즉시 평가<br>- 정기 배치 계정 및 사전 승인된 야간 작업자 화이트리스트 튜닝 |
| **`detect_traffic_spike()`** | 시간대별 트래픽 데이터 | **여러 시점의 데이터 필요** | `anomaly_detection/traffic_detection.py`<br>- 단일 시점이 아닌 시간대별(5분 버킷) 연결 빈도 집계<br>- 여러 시점의 통계 베이스라인(평균, 편차) 계산 후 동적 급증(Spike) 탐지 |
| **`detect_unauthorized_access()`** | 접근 로그와 권한 정책 | **정책 평가 결과를 이상 여부로 변환해야 함** | `anomaly_detection/advanced_detection.py`<br>- 방화벽 DENY 차단 이벤트 및 3과목 RBAC 정책(`access_control/policy.py`) 연동<br>- 인가 거부 결과를 이상 탐지 결과 객체로 변환 |
| **`detect_saas_anomaly()`** | 사용자별 SaaS 사용 기록과 기준선 | **사용자별 정상 사용 패턴 필요** | `anomaly_detection/advanced_detection.py`<br>- 사용자별 정상 서비스(`saas_user_baselines.json`), 정상 업무시간, 다운로드 빈도 대조<br>- 평소 패턴을 이탈한 심야 다운로드(`lee`) 및 급속 다운로드(`kim`) 감지 |
| **`match_ioc()`** | IP·도메인과 IOC 목록 | **IOC 일치 결과를 탐지 결과로 변환 가능** | `anomaly_detection/advanced_detection.py`<br>- `config/threat_intel.json`의 위협 인텔리전스 IP 피드 대조<br>- 일치 시 위협 행위자, 신뢰도 등 상세 컨텍스트를 포함한 탐지 객체로 변환 |
| **상관분석 함수 (`correlate_events()`)** | 여러 이벤트와 시간 범위 | **이벤트 간 관계를 평가할 데이터 필요** | `anomaly_detection/correlation.py`<br>- 단편적 알람들을 묶어 사용자/IP 축에서 시간 순서와 인과관계 평가<br>- 3단계 킬체인(초기 침투 $\rightarrow$ 비인가 정찰 $\rightarrow$ 심야 유출) 완성 시 가산점 산출 |

---

## 3. 디렉토리 구조 및 코드 구성

```
subject_4/
├── 4Readme.md                  # [본 파일] 4과목 실습 종합 가이드
├── main.py                     # Day 1 ~ Day 5 전체 실습 파이프라인 원클릭 가동 스크립트
├── config/
│   ├── detection_thresholds.json   # 탐지 임계값, 시간 윈도우, 위험점수 가중치
│   ├── threat_intel.json           # 최신 위협 인텔리전스(IoC) 악성/의심 IP 피드
│   └── saas_user_baselines.json    # 사용자별 정상 SaaS 사용 기준선 (부서, 서비스, 시간대)
├── data/
│   ├── login_logs_practice.csv     # [교재 규격] 원본 로그인 로그 (10행)
│   ├── firewall_logs_practice.csv  # [교재 규격] 원본 방화벽 트래픽 로그 (10행)
│   ├── saas_logs_practice.csv      # [교재 규격] 원본 SaaS 감사 로그 (10행)
│   ├── login_logs.csv              # 동기화된 로그인 로그
│   ├── firewall_logs.csv           # 동기화된 방화벽 로그
│   └── saas_logs.csv               # 동기화된 SaaS 로그
├── access_control/
│   ├── __init__.py
│   └── policy.py                   # [3과목 연동] RBAC 정책 및 예외 승인(evaluate_access) 모듈
├── agent_core/
│   ├── __init__.py
│   └── tool_router.py              # [Day 5] 6대 탐지 함수 및 상관분석 LLM 도구 등록 라우터
├── anomaly_detection/
│   ├── explore_logs.py             # [Day 1] CSV 결측치 및 이상 타임스탬프 진단
│   ├── normalize.py                # [Day 1] 3개 로그 정제 및 공통 스키마 정규화 (normalized_events.json)
│   ├── day01_summary.md            # [Day 1] 정규화 전/후 건수 및 무결성 분석 보고서
│   ├── login_detection.py          # [Day 2] 무차별 대입(시간 윈도우 집계) 및 심야 로그인(단일 평가)
│   ├── traffic_detection.py        # [Day 2] 여러 시점 트래픽 버킷 집계 및 베이스라인 스파이크 탐지
│   ├── day02_result.md             # [Day 2] 로그인 및 트래픽 탐지 결과 검증 보고서
│   ├── advanced_detection.py       # [Day 3] 비인가 접근 정책 변환, SaaS 패턴 이탈, IoC IP 매칭
│   ├── correlation.py              # [Day 3] 상관분석 함수, 3단계 킬체인 평가, 위험점수 산출
│   ├── day03_risk_scores.json      # [Day 3] 사용자별 다단계 공격 평가 종합 결과
│   ├── evaluation.py               # [Day 4] 30건 라벨셋 기반 오탐(FP) 원인 분석 및 튜닝
│   ├── day04_fp_analysis.md        # [Day 4] 튜닝 전 오탐 발생 원인 및 개선책 분석
│   ├── day04_tuning_result.md      # [Day 4] 튜닝 전/후 탐지 지표 비교표 (오탐 0건, 정밀도 100%)
│   ├── pipeline.py                 # [Day 5] End-to-End 전체 파이프라인 및 AI 자연어 요약
│   ├── anomaly_detection_report_20261019.json # [Day 5] 최종 침해사고 분석 통합 JSON 결과
│   ├── anomaly_detection_report_20261019.md   # [Day 5] SOC 분석가용 최종 종합 마크다운 리포트
│   └── day05_retrospective.md      # [Day 5] 전체 파이프라인 팀 리뷰 및 회고
└── tests/
    └── test_all_anomaly_detection.py # Day 1 ~ Day 5 전체 기능 단위/통합 테스트 스위트
```

---

## 4. 파이프라인 실행 방법 및 검증

### 1) 단위/통합 테스트 실행
```bash
python -m unittest tests/test_all_anomaly_detection.py
```
- **결과**: `Ran 5 tests in 0.026s, OK` (모든 테스트 통과)

### 2) Day 1 ~ Day 5 전체 실습 파이프라인 실행
```bash
python main.py
```
- 원본 30건 데이터 정제 후 22건 정규화
- `lee` 사용자의 3단계 복합 킬체인 포착 (Initial Access $\rightarrow$ Reconnaissance $\rightarrow$ Exfiltration)
- High 우선순위 위협에 대한 AI 자연어 요약 보고서 및 JSON/Markdown 산출물 자동 생성
