# SOAR 자동 대응 운영 리스크 평가표 (Risk Assessment Matrix)

## 1. 개요 및 목적
SOAR(Security Orchestration, Automation and Response) 환경에서 자동화된 보안 조치(계정 잠금, IP 차단, 세션 종료 등)가 비즈니스 연속성에 미치는 잠재적 부작용을 사전에 식별하고, 오탐(False Positive) 발생 시의 비즈니스 충격을 완화하기 위한 위험 통제 프레임워크를 수립합니다.

---

## 2. 보안 조치 유형별 운영 리스크 평가 매트릭스

| 조치 유형 | 대상 자산 | 리스크 등급 | 비즈니스 영향 분석 | 완화 통제 장치 (Mitigation Controls) | 승인 필요 여부 |
|---|---|---|---|---|---|
| **세션 강제 종료 (`terminate_session`)** | 일반/관리자 세션 | **LOW** | 사용자 작업 중 재로그인 필요 (데이터 유실 가능성 극히 미미) | 세션 무효화 전 임시 캐시 플러시 지원 | **자동 실행 (승인 불필요)** |
| **IP 인바운드 차단 (`block_ip`)** | 외부 공인 IP | **HIGH** | CDN, 결제 PG사, 기업 전용선 NAT 대역 오차단 시 대규모 결제/서비스 중단 | 화이트리스트 사전 검증, 사설 IP 및 주요 CDN IP 차단 필터링, SOC 분석가 승인 | **승인 필수 (High)** |
| **일반 계정 잠금 (`lock_account`)** | 일반 임직원 계정 | **HIGH** | 특정 임직원의 업무 일시 중단, 헬프데스크 문의 증가 | 업무 시간 외 탐지 시 자동 격리, 업무 시간 중 승인 분기 | **승인 필수 (High)** |
| **VIP 계정 잠금 (`lock_account`)** | 임원진 / 인프라 마스터 / 핵심 서비스 계정 | **CRITICAL** | 의사결정권자 연락 두절, 배치 결제 파이프라인 전면 중단 등 치명적 피해 | `config/vip_accounts.json` 등록 계정 자동 잠금 원천 차단(Exception 발생), CISO 직접 승인 필수 | **최고위 승인 필수 (Critical)** |
| **차단 해제 (`unblock_ip`, `unlock_account`)** | 복구 대상 자산 | **LOW** | 악성 공격자 재유입 가능성 | 복구 사유 기재 의무화 (`MissingReasonException`), 감사 로그 영구 보존 | **사유 필수 입력 후 즉시 실행** |

---

## 3. 오탐(False Positive) 대응 및 롤백 절차
1. **오탐 감지 및 접수**: 사용자 문의, 시스템 관제 또는 내부 감사에 의해 오탐 식별.
2. **원클릭 복구 가동 (`handle_false_positive`)**:
   - `unlock_account`: 비활성화된 계정 즉각 정상화.
   - `unblock_ip`: 방화벽 차단 정책 롤백.
3. **원인 기록 및 피드백 루프**:
   - 해제 사유 및 승인자 명시 (`containment_log.json`에 복구 이력 기록).
   - 4과목 AI/ML 보안 탐지 모델 재학습용 데이터셋(`soar/false_positive_dataset.json`)에 피처 및 정답 라벨(Ground Truth: `FALSE_POSITIVE`) 자동 추가.

---

## 4. 리스크 거버넌스 및 감사 체계
- 모든 조치는 `operator` 식별자(자동 봇 또는 승인자 ID)와 함께 타임스탬프가 불변 로그로 보관됩니다.
- 분기별로 오탐률(FP Rate)과 자동 격리 성공률을 측정하여 WAF 및 플레이북 임계치를 재조정합니다.
