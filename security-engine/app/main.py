from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List
import json

from app.schemas.models import (
    AnalyzeRequest, SecurityAnalysisResult, AskSentinelRequest, AskSentinelResponse,
    CompareRequest, CompareResponse, SecurityFinding
)
from app.parsers.parser_factory import SpecParserFactory
from app.analyzers.auth_analyzer import AuthAnalyzer
from app.analyzers.bola_analyzer import BOLAAnalyzer
from app.analyzers.bfla_analyzer import BFLAAnalyzer
from app.analyzers.sensitive_data_analyzer import SensitiveDataAnalyzer
from app.analyzers.excessive_data_analyzer import ExcessiveDataAnalyzer
from app.analyzers.http_method_analyzer import HTTPMethodAnalyzer
from app.analyzers.rate_limit_analyzer import RateLimitAnalyzer
from app.analyzers.misconfig_analyzer import MisconfigAnalyzer
from app.analyzers.input_validation_analyzer import InputValidationAnalyzer
from app.analyzers.ssrf_analyzer import SSRFAnalyzer
from app.analyzers.file_upload_analyzer import FileUploadAnalyzer
from app.analyzers.business_logic_analyzer import BusinessLogicAnalyzer
from app.analyzers.shadow_api_analyzer import ShadowAPIAnalyzer
from app.scoring.risk_calculator import RiskCalculator
from app.graph.attack_surface_builder import AttackSurfaceBuilder
from app.ai.reasoner import AIReasoner

app = FastAPI(
    title="API Sentinel - Security Analysis Engine",
    description="Enterprise AI-Assisted API Security Posture & Abuse Analysis Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "api-sentinel-security-engine",
        "engine_version": "1.0.0",
        "supported_formats": ["OpenAPI 3.0/3.1", "Swagger 2.0", "Postman Collection v2.0/v2.1"]
    }

@app.post("/analyze", response_model=SecurityAnalysisResult)
def analyze_specification(payload: AnalyzeRequest):
    if not payload.spec_content or not payload.spec_content.strip():
        raise HTTPException(status_code=400, detail="Specification content cannot be empty.")

    try:
        # Step 1: Parse Specification
        meta, endpoints = SpecParserFactory.parse_spec(payload.spec_content)
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Specification parsing failed: {str(e)}. Please check file syntax and format."
        )

    # Step 2: Execute all Security Analyzers
    findings: List[SecurityFinding] = []
    findings.extend(AuthAnalyzer.analyze(meta, endpoints))
    findings.extend(BOLAAnalyzer.analyze(meta, endpoints))
    findings.extend(BFLAAnalyzer.analyze(meta, endpoints))
    findings.extend(SensitiveDataAnalyzer.analyze(meta, endpoints))
    findings.extend(ExcessiveDataAnalyzer.analyze(meta, endpoints))
    findings.extend(HTTPMethodAnalyzer.analyze(meta, endpoints))
    findings.extend(RateLimitAnalyzer.analyze(meta, endpoints))
    findings.extend(MisconfigAnalyzer.analyze(meta, endpoints))
    findings.extend(InputValidationAnalyzer.analyze(meta, endpoints))
    findings.extend(SSRFAnalyzer.analyze(meta, endpoints))
    findings.extend(FileUploadAnalyzer.analyze(meta, endpoints))
    findings.extend(BusinessLogicAnalyzer.analyze(meta, endpoints))
    findings.extend(ShadowAPIAnalyzer.analyze(meta, endpoints))

    # Step 3: Compute Severity Summary
    sev_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.severity.upper()
        sev_summary[sev] = sev_summary.get(sev, 0) + 1

    # Step 4: Calculate Dynamic Multi-Factor Risk Score
    risk_score, risk_level, score_breakdown, category_scores = RiskCalculator.calculate_score(findings, endpoints)

    # Step 5: Construct Attack Surface Graph
    api_title = meta.get("title", payload.file_name or "API Specification")
    attack_surface = AttackSurfaceBuilder.build_graph(api_title, meta, endpoints, findings)

    # Step 6: Generate AI Executive Summary & Prioritized Action Plan
    exec_summary = AIReasoner.generate_executive_summary(api_title, risk_score, risk_level, findings, endpoints)
    recommendations = AIReasoner.generate_prioritized_recommendations(findings)

    # Step 7: Update endpoint risk levels
    for ep in endpoints:
        ep_findings = [f for f in findings if f.endpoint == ep.path or f.endpoint == f"{ep.method} {ep.path}"]
        if any(f.severity == "CRITICAL" for f in ep_findings):
            ep.risk_level = "CRITICAL"
        elif any(f.severity == "HIGH" for f in ep_findings):
            ep.risk_level = "HIGH"
        elif any(f.severity == "MEDIUM" for f in ep_findings):
            ep.risk_level = "MEDIUM"
        elif any(f.severity == "LOW" for f in ep_findings):
            ep.risk_level = "LOW"
        else:
            ep.risk_level = "INFO"

    return SecurityAnalysisResult(
        api_title=api_title,
        api_version=meta.get("version", "1.0.0"),
        spec_format=meta.get("format", "openapi_3"),
        description=meta.get("description", ""),
        servers=meta.get("servers", []),
        total_endpoints=len(endpoints),
        total_findings=len(findings),
        severity_summary=sev_summary,
        risk_score=risk_score,
        risk_level=risk_level,
        category_scores=category_scores,
        findings=findings,
        endpoints=endpoints,
        attack_surface=attack_surface,
        executive_summary=exec_summary,
        recommendations=recommendations,
        score_breakdown=score_breakdown
    )

@app.post("/ai/ask", response_model=AskSentinelResponse)
def ask_sentinel(req: AskSentinelRequest):
    findings_raw = req.context_data.get("findings", []) if req.context_data else []
    endpoints_raw = req.context_data.get("endpoints", []) if req.context_data else []

    findings = [SecurityFinding(**f) for f in findings_raw if isinstance(f, dict)]
    endpoints = [] # loaded if needed

    return AIReasoner.answer_query(
        query=req.query,
        findings=findings,
        endpoints=endpoints,
        finding_id=req.finding_id,
        endpoint_name=req.endpoint
    )

@app.post("/compare", response_model=CompareResponse)
def compare_scans(req: CompareRequest):
    base = req.base_scan
    target = req.target_scan

    base_score = int(base.get("risk_score") or base.get("riskScore") or 0)
    target_score = int(target.get("risk_score") or target.get("riskScore") or 0)
    delta = target_score - base_score
    # In security score, a decrease in risk score is an improvement
    improvement = delta < 0

    base_raw_findings = base.get("findings", [])
    target_raw_findings = target.get("findings", [])

    base_findings = {}
    for f in base_raw_findings:
        rid = f.get("rule_id") or f.get("ruleId") or ""
        ep = f.get("endpoint") or ""
        base_findings[f"{rid}_{ep}"] = f

    target_findings = {}
    for f in target_raw_findings:
        rid = f.get("rule_id") or f.get("ruleId") or ""
        ep = f.get("endpoint") or ""
        target_findings[f"{rid}_{ep}"] = f

    fixed = []
    for key, f in base_findings.items():
        if key not in target_findings:
            fixed.append(f)

    new_findings = []
    for key, f in target_findings.items():
        if key not in base_findings:
            new_findings.append(f)

    unchanged = []
    for key, f in target_findings.items():
        if key in base_findings:
            unchanged.append(f)

    sev_diff = {
        "base": base.get("severity_summary", {}),
        "target": target.get("severity_summary", {})
    }

    summary = (
        f"Compared scans: Base score was {base_score} ({base.get('risk_level', '')}), Target score is {target_score} ({target.get('risk_level', '')}). "
        f"{len(fixed)} finding(s) fixed, {len(new_findings)} new finding(s) discovered, and {len(unchanged)} unchanged."
    )

    return CompareResponse(
        base_score=base_score,
        target_score=target_score,
        score_delta=delta,
        improvement=improvement,
        findings_fixed=fixed,
        findings_new=new_findings,
        findings_unchanged=unchanged,
        severity_diff=sev_diff,
        summary=summary
    )

@app.get("/rules")
def get_security_rules():
    """Returns the full catalog of OWASP API Security Top 10 rules implemented in API Sentinel"""
    return {
        "total_rules": 26,
        "categories": [
            "Authentication",
            "Authorization",
            "Sensitive Data Exposure",
            "Excessive Data Exposure",
            "HTTP Method Security",
            "Rate Limiting & Abuse Prevention",
            "Security Misconfiguration",
            "Input Validation & Data Integrity",
            "Server-Side Request Forgery",
            "File Upload Security",
            "Business Logic & Anti-Abuse",
            "API Inventory & Zombie APIs"
        ],
        "rules": [
            {"id": "API-AUTH-001", "name": "Missing Authentication Requirement", "owasp": "API2:2023 Broken Authentication"},
            {"id": "API-AUTH-002", "name": "Unauthenticated Administrative Endpoint", "owasp": "API5:2023 Broken Function Level Authorization"},
            {"id": "API-AUTH-003", "name": "HTTP Basic Authentication in Production", "owasp": "API2:2023 Broken Authentication"},
            {"id": "API-BOLA-001", "name": "Direct Object Identifier Exposure (BOLA/IDOR)", "owasp": "API1:2023 Broken Object Level Authorization"},
            {"id": "API-BOLA-002", "name": "Predictable Sequential Integer Identifier", "owasp": "API1:2023 Broken Object Level Authorization"},
            {"id": "API-BFLA-001", "name": "Privileged Path Missing Granular Scopes", "owasp": "API5:2023 Broken Function Level Authorization"},
            {"id": "API-BFLA-003", "name": "Privilege Escalation Endpoint Pattern", "owasp": "API5:2023 Broken Function Level Authorization"},
            {"id": "API-DATA-001", "name": "Secret / Password Hash Exposed in Response Schema", "owasp": "API3:2023 Broken Object Property Level Authorization"},
            {"id": "API-DATA-002", "name": "PII / Financial Identifier Exposed in Response", "owasp": "API3:2023 Broken Object Property Level Authorization"},
            {"id": "API-DATA-003", "name": "Sensitive Token / Key in URL Query Parameter", "owasp": "API3:2023 Broken Object Property Level Authorization"},
            {"id": "API-EXCESS-001", "name": "Internal Backend Metadata in Response Schema", "owasp": "API3:2023 Broken Object Property Level Authorization"},
            {"id": "API-HTTP-001", "name": "State Mutation Over HTTP GET", "owasp": "API8:2023 Security Misconfiguration"},
            {"id": "API-RATE-001", "name": "Sensitive Flow Missing Documented Rate Limiting", "owasp": "API4:2023 Unrestricted Resource Consumption"},
            {"id": "API-CONF-001", "name": "Insecure Cleartext HTTP Server URL", "owasp": "API8:2023 Security Misconfiguration"},
            {"id": "API-CONF-003", "name": "Stack Trace / Debug Leakage in 500 Error Schema", "owasp": "API8:2023 Security Misconfiguration"},
            {"id": "API-VAL-001", "name": "Unconstrained String Parameter Without Bounds", "owasp": "API8:2023 Security Misconfiguration"},
            {"id": "API-VAL-003", "name": "Unbounded Array Payload in Request Body", "owasp": "API4:2023 Unrestricted Resource Consumption"},
            {"id": "API-SSRF-001", "name": "Server-Side Request Forgery via URL Parameter", "owasp": "API7:2023 Server Side Request Forgery"},
            {"id": "API-UPLOAD-001", "name": "File Upload Endpoint Missing MIME / Size Guard", "owasp": "API8:2023 Security Misconfiguration"},
            {"id": "API-BIZ-001", "name": "Sensitive Financial Transaction Flow", "owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows"},
            {"id": "API-BIZ-002", "name": "Coupon / Incentive Race Condition Risk", "owasp": "API6:2023 Unrestricted Access to Sensitive Business Flows"},
            {"id": "API-VER-001", "name": "Deprecated Endpoint Maintained Active", "owasp": "API9:2023 Improper Inventory Management"},
            {"id": "API-VER-002", "name": "Multiple Legacy API Versions Coexisting", "owasp": "API9:2023 Improper Inventory Management"},
            {"id": "API-VER-003", "name": "Internal / Test Route in Production Contract", "owasp": "API9:2023 Improper Inventory Management"}
        ]
    }
