import uuid
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class BFLAAnalyzer:
    SENSITIVE_PATHS = [
        "admin", "administrator", "manage", "management", "settings",
        "roles", "permissions", "privileges", "promote", "demote",
        "impersonate", "audit", "system-config", "keys", "secrets",
        "users/delete", "users/block", "tenants/delete", "override"
    ]

    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            path_lower = ep.path.lower()
            matched_keywords = [k for k in BFLAAnalyzer.SENSITIVE_PATHS if k in path_lower]

            if matched_keywords:
                kw_str = ", ".join(matched_keywords)
                
                # Check declared security scopes / roles
                has_granular_scopes = False
                declared_scopes = []
                for sec in ep.security_requirements:
                    for scheme_name, scopes in sec.items():
                        if scopes:
                            declared_scopes.extend(scopes)
                            has_granular_scopes = True

                # Case 1: Destructive or administrative operation without granular role scopes
                is_destructive = ep.method in ["DELETE", "PUT", "PATCH", "POST"]
                if not has_granular_scopes:
                    severity = "HIGH" if (is_destructive or "admin" in path_lower or "promote" in path_lower) else "MEDIUM"
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        rule_id="API-BFLA-001",
                        title="Potential Broken Function Level Authorization (BFLA)",
                        category="Authorization",
                        severity=severity,
                        confidence=0.88,
                        endpoint=ep.path,
                        method=ep.method,
                        description=f"Endpoint '{ep.method} {ep.path}' performs privileged operations (keywords: {kw_str}) but does not document granular role requirements or RBAC scopes in the API specification.",
                        evidence=f"Sensitive path matches [{kw_str}]. Declared security scopes: {declared_scopes if declared_scopes else 'None (Universal / Standard User Token)'}.",
                        impact="If the application only checks if the user is authenticated without validating role permissions (e.g. ROLE_ADMIN vs ROLE_USER), standard users could execute administrative functions.",
                        recommendation="Enforce strict Role-Based Access Control (RBAC) / Attribute-Based Access Control (ABAC) middleware. Validate user claims on every administrative endpoint.",
                        fix_code_example="""// Express.js RBAC Middleware Example
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

// Attach to admin routes:
router.post('/admin/users/promote', authenticateToken, requireRole('SUPER_ADMIN'), promoteUserHandler);""",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                            "https://cwe.mitre.org/data/definitions/285.html"
                        ],
                        cwe_id="CWE-285",
                        owasp_category="API5:2023 Broken Function Level Authorization"
                    ))

                # Case 2: Privilege escalation verbs in route
                if any(verb in path_lower for verb in ["promote", "grant", "elevate", "impersonate"]):
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        rule_id="API-BFLA-003",
                        title="High-Risk Privilege Escalation Endpoint Pattern",
                        category="Authorization",
                        severity="HIGH",
                        confidence=0.92,
                        endpoint=ep.path,
                        method=ep.method,
                        description=f"Endpoint '{ep.method} {ep.path}' appears to perform user privilege assignment or identity assumption.",
                        evidence=f"Privilege modification keyword identified in route path: {ep.path}.",
                        impact="Flaws in privilege modification handlers permit standard attackers to self-elevate to administrative status.",
                        recommendation="Require multi-factor authentication (MFA) step-up and enforce immutable server-side hierarchy validation for role assignment.",
                        fix_code_example="""// Require MFA step-up verification for privilege escalation
router.post('/users/:id/promote', authenticateToken, requireMfaVerification, requireRole('SUPER_ADMIN'), async (req, res) => {
  // Never allow standard users to grant admin permissions
  await grantAdminRole(req.params.id, req.user.id);
  res.json({ status: 'Role updated' });
});""",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
                        cwe_id="CWE-269",
                        owasp_category="API5:2023 Broken Function Level Authorization"
                    ))

        return findings
