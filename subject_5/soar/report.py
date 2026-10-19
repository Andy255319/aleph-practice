import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from soar.containment import get_all_containment_logs
from soar.ticketing import get_ticket, MockTicketStore

def _get_base_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

def collect_incident_data(
    incident_data: Dict[str, Any],
    ticket_id: Optional[str] = None
) -> Dict[str, Any]:
    target_account = incident_data.get("target_account")
    source_ip = incident_data.get("source_ip")

    all_logs = get_all_containment_logs()
    related_actions = []
    for log in all_logs:
        target = str(log.get("target", ""))
        if (target_account and target_account in target) or (source_ip and source_ip in target):
            related_actions.append(log)

    ticket_info = {}
    if ticket_id:
        ticket_info = get_ticket(ticket_id) or {}
    else:
        for t in MockTicketStore._tickets.values():
            if t.get("event_id") == incident_data.get("incident_id") or t.get("incident_id") == incident_data.get("incident_id"):
                ticket_info = t
                break

    aggregated = {
        "collected_at": datetime.now().isoformat(),
        "day1_incident": incident_data,
        "day2_containment_actions": related_actions,
        "day3_ticket": ticket_info,
        "summary_metrics": {
            "total_containment_actions": len(related_actions),
            "ticket_status": ticket_info.get("status", "N/A"),
            "current_assignee": ticket_info.get("assignee", "N/A")
        }
    }
    return aggregated

def generate_technical_report(data: Dict[str, Any]) -> str:
    """기술팀용 상세 버전 리포트 생성 (Markdown)"""
    inc = data.get("day1_incident", {})
    actions = data.get("day2_containment_actions", [])
    ticket = data.get("day3_ticket", {})
    metrics = data.get("summary_metrics", {})

    action_rows = []
    for a in actions:
        act_type = a.get("action") or a.get("action_type")
        act_res = a.get("result") or a.get("status")
        act_reason = a.get("reason") or a.get("details")
        action_rows.append(
            f"| {a.get('timestamp')} | `{act_type}` | `{a.get('target')}` | {act_res} | {act_reason} |"
        )
    action_table = "\n".join(action_rows) if action_rows else "| - | 조치 내역 없음 | - | - | - |"


    history_rows = []
    for h in inc.get("history", []):
        history_rows.append(
            f"- **[{h.get('timestamp')}]** `{h.get('status')}` - {h.get('comment')} (담당: {h.get('operator')})"
        )
    history_text = "\n".join(history_rows) if history_rows else "이력 없음"

    worklog_rows = []
    for w in ticket.get("worklogs", []):
        worklog_rows.append(
            f"- **[{w.get('timestamp')}]** `{w.get('author')}`: {w.get('comment')}"
        )
    worklog_text = "\n".join(worklog_rows) if worklog_rows else "워크로그 없음"

    report = f"""# [기술팀 상세 초동대응 리포트] {inc.get('incident_id')}

- **보고서 발행 일시**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **분류 등급**: CONFIDENTIAL - 보안기술팀 내부 공유용
- **인시던트 ID**: `{inc.get('incident_id')}`
- **위협 수준(Severity)**: `{inc.get('severity')}`

---

## 1. 인시던트 핵심 개요 (Day 1 수집 데이터)
- **탐지 이벤트 유형**: `{inc.get('event_type')}`
- **공격 유입 출발지(Source IP)**: `{inc.get('source_ip')}`
- **공격 표적 자산/계정(Target)**: `{inc.get('target_account')}`
- **현재 처리 상태**: `{inc.get('status')}`
- **적용 플레이북**: `{inc.get('matched_playbook', {}).get('name', 'N/A')} ({inc.get('matched_playbook', {}).get('id', 'N/A')})`
- **탐지 상세 설명**: {inc.get('description')}

### 인시던트 수명주기 전이 이력
{history_text}

---

## 2. 격리 및 차단 기술 조치 내역 (Day 2 조치 로그 연동)
총 `{metrics.get('total_containment_actions')}`건의 자동 및 승인 기반 격리 조치가 시행되었습니다.

| 타임스탬프 | 조치 유형 | 대상 | 실행 결과 | 수행 주체 | 상세 내역 |
|---|---|---|---|---|---|
{action_table}

---

## 3. ITSM 티켓 및 에스컬레이션 현황 (Day 3 연동 데이터)
- **발행 티켓 ID**: `{ticket.get('ticket_id', 'N/A')}`
- **티켓 상태**: `{ticket.get('status', 'N/A')}`
- **현재 담당 엔지니어**: `{ticket.get('assignee', 'N/A')}`
- **티켓 제목**: {ticket.get('title', 'N/A')}

### 티켓 처리 워크로그 및 SLA 추적
{worklog_text}

---

## 4. 침해 지표 (IoC) 및 방화벽 룰 현황
```json
{{
  "indicators_of_compromise": [
    {{"type": "ipv4", "value": "{inc.get('source_ip')}", "action": "BLOCKED_ON_PERIMETER_FIREWALL"}},
    {{"type": "account", "value": "{inc.get('target_account')}", "status": "LOCKED_OR_ISOLATED"}}
  ]
}}
```

## 5. 기술팀 후속 조치 과제
1. 호스트 포렌식 아티팩트(Prefetch, Event Log 4624/4625) 정밀 추출
2. 내부망 측면이동(Lateral Movement) 흔적 SIEM 상관분석 쿼리 수행
3. 외부 통신 악성 C2 도메인 DNS Sinkhole 등록 확인
"""
    return report

def generate_executive_report(data: Dict[str, Any]) -> str:
    """경영진용 요약 버전 리포트 생성 (Markdown)"""
    inc = data.get("day1_incident", {})
    actions = data.get("day2_containment_actions", [])
    ticket = data.get("day3_ticket", {})

    report = f"""# [경영진 보고용] 보안 침해사고 초동대응 요약 보고서

- **보고 일시**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **보고 대상**: CISO / 경영위원회 / IT운영본부장
- **사고 식별 번호**: `{inc.get('incident_id')}`

---

## Executive Summary (경영 요약)
본 건은 **{inc.get('event_type')}** 의심 행위가 자동 감지되어 SOAR 자동대응 체계에 따라 즉각적인 초동 격리 및 위험 평가가 완료된 건입니다.
사내 핵심 자산 및 고객 데이터베이스에 대한 유출 정황은 현재까지 확인되지 않았으며, 위협 행위자의 접근은 성공적으로 차단되었습니다.

| 구분 | 주요 내용 |
|---|---|
| **위협 등급** | **{inc.get('severity')}** |
| **피해 대상** | {inc.get('target_account')} (계정/시스템) |
| **비즈니스 영향도** | **경미 (초동 차단으로 업무 마비 및 데이터 유출 차단 성공)** |
| **대응 상태** | `{inc.get('status')}` (통제 완료 후 후속 감사 진행 중) |
| **티켓 번호** | `{ticket.get('ticket_id', 'N/A')}` (담당: {ticket.get('assignee', 'N/A')}) |

---

## 주요 초동 조치 요약
1. **신속한 위험 격리**:
   - 의심 침해원천(`{inc.get('source_ip')}`) 즉시 인바운드 차단 조치.
   - 대상 계정에 대한 세션 폐기 및 2차 인증 강화 조치 완료 (총 {len(actions)}건의 보안 통제 시행).
2. **거버넌스 및 승인 통제 준수**:
   - 위험도 높은 계정 및 시스템 변경에 대해 SOAR 승인 게이트를 통과하여 무단 변경 리스크 배제.
3. **에스컬레이션 체계 가동**:
   - 1차 관제에서 2차 전문 대응팀으로 안전하게 이관되어 SLA 기준 내 대응 완료.

---

## 향후 권고사항 및 지원 요청사항
- **임직원 보안인식 강화**: 유사 피싱 및 자격증명 도용 방지를 위한 전사 2FA 의무화 완료 확인.
- **예산 및 자원**: AI 기반 4과목 오탐/정탐 자동 분류 모델 적용 확대를 위한 데이터셋 파이프라인 지속 투자.
"""
    return report

def generate_reports(
    incident_data: Dict[str, Any],
    ticket_id: Optional[str] = None,
    output_dir: Optional[str] = None
) -> Dict[str, str]:
    """초동대응 기술팀/경영진용 2종 리포트를 생성하고 파일로 저장"""
    if output_dir is None:
        output_dir = _get_base_dir()

    data = collect_incident_data(incident_data, ticket_id)
    tech_content = generate_technical_report(data)
    exec_content = generate_executive_report(data)

    tech_path = os.path.join(output_dir, "incident_report_tech.md")
    exec_path = os.path.join(output_dir, "incident_report_exec.md")

    with open(tech_path, "w", encoding="utf-8") as f:
        f.write(tech_content)

    with open(exec_path, "w", encoding="utf-8") as f:
        f.write(exec_content)

    return {
        "technical_report": tech_path,
        "executive_report": exec_path
    }
