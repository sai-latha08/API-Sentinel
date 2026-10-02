from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime, timezone

class ParameterSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    name: str
    in_location: str = Field(alias="in")  # query, path, header, cookie
    required: bool = False
    param_type: str = "string"
    format: Optional[str] = None
    description: Optional[str] = None
    schema_details: Optional[Dict[str, Any]] = None

class RequestBodySchema(BaseModel):
    required: bool = False
    content_types: List[str] = []
    schema_details: Optional[Dict[str, Any]] = None
    example: Optional[Any] = None

class ResponseSchema(BaseModel):
    status_code: str
    description: Optional[str] = None
    content_types: List[str] = []
    headers: List[str] = []
    schema_details: Optional[Dict[str, Any]] = None

class EndpointDefinition(BaseModel):
    id: str
    path: str
    method: str
    summary: Optional[str] = None
    description: Optional[str] = None
    operation_id: Optional[str] = None
    tags: List[str] = []
    security_requirements: List[Dict[str, List[str]]] = []
    is_authenticated: bool = False
    parameters: List[ParameterSchema] = []
    request_body: Optional[RequestBodySchema] = None
    responses: List[ResponseSchema] = []
    is_deprecated: bool = False
    sensitivity_score: float = 0.0  # 0.0 to 1.0
    sensitivity_reasons: List[str] = []
    risk_level: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, INFO

class SecurityFinding(BaseModel):
    id: str
    rule_id: str
    title: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float  # 0.0 to 1.0
    endpoint: str
    method: str
    description: str
    evidence: str
    impact: str
    recommendation: str
    fix_code_example: Optional[str] = None
    references: List[str] = []
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    detection_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class GraphNode(BaseModel):
    id: str
    type: str  # apiRoot, authScheme, endpoint, sensitiveResource, riskFinding
    position: Dict[str, float]
    data: Dict[str, Any]

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = None
    animated: bool = False
    style: Optional[Dict[str, Any]] = None

class AttackSurfaceGraph(BaseModel):
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []

class ScoreFactor(BaseModel):
    name: str
    impact: str
    points: float
    description: str

class ScoreBreakdown(BaseModel):
    base_score: float
    critical_penalty: float
    high_penalty: float
    medium_penalty: float
    low_penalty: float
    info_penalty: float
    sensitivity_multiplier: float
    factors: List[ScoreFactor] = []

class SecurityAnalysisResult(BaseModel):
    api_title: str
    api_version: str
    spec_format: str  # openapi_3, swagger_2, postman
    description: Optional[str] = None
    servers: List[str] = []
    total_endpoints: int
    total_findings: int
    severity_summary: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }
    risk_score: int  # 0 - 100
    risk_level: str  # Excellent, Good, Moderate, High Risk, Critical Risk
    category_scores: Dict[str, int] = {}
    findings: List[SecurityFinding] = []
    endpoints: List[EndpointDefinition] = []
    attack_surface: AttackSurfaceGraph = AttackSurfaceGraph()
    executive_summary: str = ""
    recommendations: List[Dict[str, Any]] = []
    score_breakdown: ScoreBreakdown
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AnalyzeRequest(BaseModel):
    spec_content: str
    file_name: Optional[str] = "api_specification"
    file_type: Optional[str] = "json"  # json, yaml

class AskSentinelRequest(BaseModel):
    query: str
    finding_id: Optional[str] = None
    endpoint: Optional[str] = None
    context_data: Optional[Dict[str, Any]] = None

class AskSentinelResponse(BaseModel):
    answer: str
    confidence: float
    grounded_evidence: List[str] = []
    remediation_suggestion: Optional[str] = None
    relevant_rules: List[str] = []
    code_snippet: Optional[str] = None

class CompareRequest(BaseModel):
    base_scan: Dict[str, Any]
    target_scan: Dict[str, Any]

class CompareResponse(BaseModel):
    base_score: int
    target_score: int
    score_delta: int
    improvement: bool
    findings_fixed: List[Dict[str, Any]] = []
    findings_new: List[Dict[str, Any]] = []
    findings_unchanged: List[Dict[str, Any]] = []
    severity_diff: Dict[str, Dict[str, int]] = {}
    summary: str
