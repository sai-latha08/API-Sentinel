import uuid
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class AuthAnalyzer:
    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        global_security = meta.get("global_security", [])
        security_schemes = meta.get("security_schemes", {})

        # Rule API-AUTH-005: Missing global security definitions
        if not security_schemes and not global_security:
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()),
                rule_id="API-AUTH-005",
                title="Missing Global Security Schemes in Specification",
                category="Authentication",
                severity="MEDIUM",
                confidence=0.95,
                endpoint="Global API Specification",
                method="GLOBAL",
                description="The API specification does not declare any security schemes (such as OAuth 2.0, OpenID Connect, JWT Bearer, or API Keys) in its components/securityDefinitions.",
                evidence="No 'securitySchemes' or 'securityDefinitions' block found in root components.",
                impact="Consumers and automated gateways cannot enforce a standardized authentication protocol, leading to inadvertent public exposure of API routes.",
                recommendation="Define standard authentication schemes (e.g., Bearer JWT or OAuth 2.0) in components.securitySchemes and declare global security requirements.",
                fix_code_example="""components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
security:
  - BearerAuth: []""",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                cwe_id="CWE-306",
                owasp_category="API2:2023 Broken Authentication"
            ))

        # Check weak auth schemes (Basic auth)
        for s_name, s_def in security_schemes.items():
            if isinstance(s_def, dict):
                s_type = str(s_def.get("type", "")).lower()
                s_scheme = str(s_def.get("scheme", "")).lower()
                if s_scheme == "basic" or s_type == "basic":
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        rule_id="API-AUTH-003",
                        title="HTTP Basic Authentication Declared",
                        category="Authentication",
                        severity="MEDIUM",
                        confidence=0.90,
                        endpoint=f"Scheme: {s_name}",
                        method="GLOBAL",
                        description="HTTP Basic authentication transmits credentials encoded in Base64 with every request. Unless strictly combined with modern token rotation and TLS, it is vulnerable to credential replay and brute-forcing.",
                        evidence=f"Security scheme '{s_name}' uses scheme='basic'.",
                        impact="Credentials exposed in headers, vulnerability to credential stuffing, and lack of fine-grained token revocation.",
                        recommendation="Migrate from Basic Auth to short-lived JSON Web Tokens (JWT) or OAuth 2.0 authorization code flow.",
                        fix_code_example="""components:
  securitySchemes:
    OAuth2Auth:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://auth.example.com/oauth/authorize
          tokenUrl: https://auth.example.com/oauth/token
          scopes:
            read:profile: Read profile info
            write:orders: Create orders""",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
                        cwe_id="CWE-287",
                        owasp_category="API2:2023 Broken Authentication"
                    ))

        # Endpoint-level authentication checks
        for ep in endpoints:
            path_lower = ep.path.lower()
            is_admin = any(w in path_lower for w in ["admin", "administrator", "manage", "root", "system", "internal", "roles"])
            is_auth_flow = any(w in path_lower for w in ["login", "register", "signup", "oauth/token", "forgot-password", "health", "metrics", "docs", "ping"])

            # Rule API-AUTH-002: Administrative Endpoint without Security Requirements
            if is_admin and not ep.is_authenticated:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-AUTH-002",
                    title="Administrative Endpoint Missing Security Requirement",
                    category="Authentication",
                    severity="CRITICAL",
                    confidence=0.95,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Endpoint '{ep.method} {ep.path}' appears to expose administrative or privileged functionality but has no declared authentication or security requirement in the API specification.",
                    evidence=f"Path contains administrative keyword '{path_lower}', but security requirements are empty ([]).",
                    impact="Unauthorized threat actors could access administrative control planes, modify user roles, or extract sensitive platform telemetry.",
                    recommendation="Enforce mandatory authentication and strict role-based authorization (RBAC) at the gateway and controller level.",
                    fix_code_example=f"""# OpenAPI Route Security
paths:
  {ep.path}:
    {ep.method.lower()}:
      security:
        - BearerAuth: [admin:write, system:manage]""",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
                    cwe_id="CWE-306",
                    owasp_category="API5:2023 Broken Function Level Authorization"
                ))

            # Rule API-AUTH-001: Missing Declared Authentication on Non-Public Routes
            elif not is_auth_flow and not ep.is_authenticated:
                # Calculate contextual severity
                sev = "HIGH" if ep.sensitivity_score >= 0.6 else ("MEDIUM" if ep.sensitivity_score >= 0.4 else "LOW")
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-AUTH-001",
                    title="Potential Missing Authentication Requirement",
                    category="Authentication",
                    severity=sev,
                    confidence=0.88,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Endpoint '{ep.method} {ep.path}' does not declare an explicit security requirement. If this route is intended to serve private user or business data, unauthenticated access represents an access control gap.",
                    evidence=f"Security array is missing or empty. Sensitivity score: {ep.sensitivity_score}.",
                    impact="Potential unauthenticated data access, state mutation, or unauthorized resource manipulation.",
                    recommendation="If this endpoint is private, add declared security schemes. If public by design, annotate the endpoint description explicitly as public.",
                    fix_code_example=f"""paths:
  {ep.path}:
    {ep.method.lower()}:
      security:
        - BearerAuth: []""",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
                    cwe_id="CWE-306",
                    owasp_category="API2:2023 Broken Authentication"
                ))

        return findings
