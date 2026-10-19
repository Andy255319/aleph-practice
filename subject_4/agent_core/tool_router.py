"""
Agent Core Tool Router Module
AI 에이전트 및 LLM 도구 호출(Tool Calling) 연동 라우터
(Day 4 슬라이드 표 명세 6대 탐지 함수 및 상관분석 함수 완벽 등록)
"""
from typing import Dict, Any, Callable, Optional

class ToolRouter:
    """이상탐지 핵심 함수들을 LLM 에이전트의 액션 도구(Tool)로 등록하고 디스패치하는 라우터"""
    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}

    def register_tool(self, name: str, func: Callable, description: str, parameters: Optional[Dict[str, Any]] = None):
        self._tools[name] = {
            "name": name,
            "func": func,
            "description": description,
            "parameters": parameters or {}
        }

    def execute_tool(self, name: str, **kwargs) -> Any:
        if name not in self._tools:
            raise KeyError(f"등록되지 않은 도구 호출: {name}. 등록 도구: {list(self._tools.keys())}")
        return self._tools[name]["func"](**kwargs)

    def list_tools(self) -> Dict[str, Any]:
        return {
            name: {
                "description": info["description"],
                "parameters": info["parameters"]
            }
            for name, info in self._tools.items()
        }

# 글로벌 싱글톤 라우터
global_router = ToolRouter()

def register_anomaly_tools():
    """이상탐지 모듈의 핵심 함수들을 글로벌 라우터에 자동 등록"""
    from anomaly_detection.login_detection import detect_bruteforce, detect_offhour_login
    from anomaly_detection.traffic_detection import detect_traffic_spike
    from anomaly_detection.advanced_detection import match_ioc, detect_unauthorized_access, detect_saas_anomaly
    from anomaly_detection.correlation import correlate_events, calculate_risk_score

    # 1. detect_bruteforce()
    global_router.register_tool(
        name="detect_bruteforce",
        func=detect_bruteforce,
        description="사용자별 로그인 로그와 시간 범위를 분석하여 무차별 대입 공격 및 계정 탈취를 탐지합니다."
    )
    # 2. detect_offhour_login()
    global_router.register_tool(
        name="detect_offhour_login",
        func=detect_offhour_login,
        description="로그인 로그 개별 이벤트를 평가하여 업무 외 시간(심야/새벽) 비인가 접속을 탐지합니다."
    )
    # 3. detect_traffic_spike()
    global_router.register_tool(
        name="detect_traffic_spike",
        func=detect_traffic_spike,
        description="시간대별 여러 시점의 트래픽 데이터를 통계 베이스라인과 비교하여 급증(Spike)을 탐지합니다."
    )
    # 4. detect_unauthorized_access()
    global_router.register_tool(
        name="detect_unauthorized_access",
        func=detect_unauthorized_access,
        description="접근 로그와 권한 정책(RBAC/방화벽)을 대조하여 비인가 리소스 접근 이상 여부로 변환합니다."
    )
    # 5. detect_saas_anomaly()
    global_router.register_tool(
        name="detect_saas_anomaly",
        func=detect_saas_anomaly,
        description="사용자별 SaaS 사용 기록과 정상 패턴 기준선을 비교하여 이상 행위 및 심야 유출을 탐지합니다."
    )
    # 6. match_ioc()
    global_router.register_tool(
        name="match_ioc",
        func=match_ioc,
        description="IP·도메인을 위협 인텔리전스(IOC) 목록과 매칭하여 탐지 결과로 변환합니다."
    )
    # 7. correlate_events() (상관분석 함수)
    global_router.register_tool(
        name="correlate_events",
        func=correlate_events,
        description="여러 이벤트와 시간 범위를 종합하여 이벤트 간 관계를 평가하고 다단계 킬체인을 상관분석합니다."
    )
    global_router.register_tool(
        name="calculate_risk_score",
        func=calculate_risk_score,
        description="탐지된 복합 이상 징후 가중치와 킬체인 완성 여부를 종합하여 통합 위험점수를 산출합니다."
    )

# 패키지 로드 시 자동 등록
register_anomaly_tools()
