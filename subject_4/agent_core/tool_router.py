"""
Agent Core Tool Router Module
AI 에이전트 및 LLM 도구 호출(Tool Calling) 연동 라우터
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
    from anomaly_detection.correlation import calculate_risk_score

    global_router.register_tool(
        name="detect_bruteforce",
        func=detect_bruteforce,
        description="다중 로그인 실패를 분석하여 무차별 대입 공격을 식별합니다."
    )
    global_router.register_tool(
        name="detect_traffic_spike",
        func=detect_traffic_spike,
        description="통계적 베이스라인을 기반으로 비정상 네트워크 트래픽 급증을 탐지합니다."
    )
    global_router.register_tool(
        name="match_ioc",
        func=match_ioc,
        description="최신 위협 인텔리전스(IoC) 데이터베이스와 인입 IP를 대조합니다."
    )
    global_router.register_tool(
        name="detect_saas_anomaly",
        func=detect_saas_anomaly,
        description="SaaS 클라우드 내 대량 파일 다운로드 및 권한 상승 이상을 탐지합니다."
    )
    global_router.register_tool(
        name="calculate_risk_score",
        func=calculate_risk_score,
        description="사용자별 탐지 지표와 상관분석 킬체인을 종합하여 위험점수를 산출합니다."
    )

# 패키지 로드 시 자동 등록
register_anomaly_tools()
