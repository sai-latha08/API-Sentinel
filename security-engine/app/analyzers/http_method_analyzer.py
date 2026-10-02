import uuid
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class HTTPMethodAnalyzer:
    STATE_CHANGING_KEYWORDS = [
        "delete", "remove", "destroy", "drop", "terminate", "kill",
        "update", "modify", "edit", "change", "create", "insert",
        "promote", "transfer", "pay", "charge", "refund", "execute", "run"
    ]

    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            path_lower = ep.path.lower()
            
            # Rule API-HTTP-001: State changing action on GET method
            if ep.method == "GET":
                matched_mutations = [w for w in HTTPMethodAnalyzer.STATE_CHANGING_KEYWORDS if f"/{w}" in path_lower or f"_{w}" in path_lower or path_lower.endswith(w)]
                if matched_mutations:
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        rule_id="API-HTTP-001",
                        title="Potential State-Changing Operation Using HTTP GET",
                        category="HTTP Method Security",
                        severity="HIGH",
                        confidence=0.88,
                        endpoint=ep.path,
                        method=ep.method,
                        description=f"Endpoint '{ep.method} {ep.path}' appears to perform state-changing or destructive actions (keywords: {matched_mutations}) over an HTTP GET method.",
                        evidence=f"GET method paired with mutation action keyword: {matched_mutations}.",
                        impact="HTTP GET requests are safe and idempotent by HTTP RFC specification. Using GET for state mutation makes the route vulnerable to Cross-Site Request Forgery (CSRF) via simple <img> or <a> tags, search crawler pre-fetching, and proxy caching.",
                        recommendation="Use appropriate HTTP verbs (POST for creation, PUT/PATCH for updates, DELETE for removals). Never execute state-changing actions via GET.",
                        fix_code_example="""// Insecure:
GET /users/123/delete

// Secure:
DELETE /users/123
Authorization: Bearer <token>""",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
                        cwe_id="CWE-352",
                        owasp_category="API8:2023 Security Misconfiguration"
                    ))

            # Rule API-HTTP-002: Insecure / Dangerous HTTP Verbs (TRACE / CONNECT)
            if ep.method in ["TRACE", "CONNECT"]:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-HTTP-002",
                    title=f"Dangerous HTTP Method '{ep.method}' Enabled in Specification",
                    category="HTTP Method Security",
                    severity="MEDIUM",
                    confidence=0.95,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Endpoint '{ep.method} {ep.path}' exposes HTTP {ep.method}. TRACE methods can be exploited for Cross-Site Tracing (XST) attacks to bypass HttpOnly cookies.",
                    evidence=f"Method '{ep.method}' declared in API route definition.",
                    impact="Potential credential reflection and cookie theft through XST attacks.",
                    recommendation="Disable TRACE and CONNECT HTTP methods globally in the web server / API gateway.",
                    fix_code_example="""# Nginx Configuration
if ($request_method ~ ^(TRACE|CONNECT)$) {
    return 405;
}""",
                    references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                    cwe_id="CWE-693",
                    owasp_category="API8:2023 Security Misconfiguration"
                ))

        return findings
