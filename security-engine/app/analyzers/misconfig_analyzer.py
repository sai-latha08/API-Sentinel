import uuid
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding
from app.analyzers.sensitive_data_analyzer import SensitiveDataAnalyzer

class MisconfigAnalyzer:
    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        servers = meta.get("servers", [])

        # Rule API-CONF-001: Insecure HTTP Cleartext URL Scheme
        http_servers = [s for s in servers if s.startswith("http://") and not s.startswith("http://localhost") and not s.startswith("http://127.0.0.1")]
        if http_servers:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()),
                rule_id="API-CONF-001",
                title="Insecure Plaintext HTTP Server URL Configured",
                category="Security Misconfiguration",
                severity="HIGH",
                confidence=0.98,
                endpoint="Server Configuration",
                method="GLOBAL",
                description=f"The API specification lists server endpoint(s) utilizing unencrypted HTTP transport: [{', '.join(http_servers)}].",
                evidence=f"Server URLs contain unencrypted 'http://' scheme: {http_servers}.",
                impact="Cleartext communications are subject to Man-in-the-Middle (MitM) eavesdropping, session token theft, and payload tampering across public networks.",
                recommendation="Enforce HTTPS across all server configurations and configure HTTP Strict Transport Security (HSTS).",
                fix_code_example="""servers:
  - url: https://api.example.com/v1
    description: Secure Production API (TLS 1.3)""",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
                cwe_id="CWE-319",
                owasp_category="API8:2023 Security Misconfiguration"
            ))

        # Check error response schemas for stack trace / debug info leakage
        for ep in endpoints:
            for resp in ep.responses:
                if resp.status_code in ["500", "502", "503", "default"]:
                    if resp.schema_details:
                        props = SensitiveDataAnalyzer._extract_property_names(resp.schema_details)
                        stack_props = [p for p in props if p.lower() in ["stacktrace", "stack_trace", "exception", "debugtrace", "rawerror", "sqlexception"]]
                        if stack_props:
                            findings.append(SecurityFinding(
                                id=str(uuid.uuid4()),
                                rule_id="API-CONF-003",
                                title="Verbose Error Response Schema (Stack Trace / Debug Leakage)",
                                category="Security Misconfiguration",
                                severity="LOW",
                                confidence=0.85,
                                endpoint=ep.path,
                                method=ep.method,
                                description=f"Error response schema ({resp.status_code}) on '{ep.method} {ep.path}' declares debugging properties: [{', '.join(stack_props)}].",
                                evidence=f"Schema properties matched: {stack_props} on status {resp.status_code}.",
                                impact="Exposing internal stack traces reveals framework versions, local file system paths, database queries, and code lines to attackers.",
                                recommendation="Return sanitized, RFC 7807 problem details with generic error codes in production environments.",
                                fix_code_example="""// Secure Error Handling
app.use((err, req, res, next) => {
  logger.error(err); // Log internally
  res.status(500).json({
    type: 'https://api.example.com/errors/internal-error',
    title: 'An unexpected internal error occurred',
    status: 500,
    requestId: req.id
  });
});""",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"],
                                cwe_id="CWE-209",
                                owasp_category="API8:2023 Security Misconfiguration"
                            ))

        return findings
