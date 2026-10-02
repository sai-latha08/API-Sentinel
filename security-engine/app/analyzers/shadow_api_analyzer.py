import uuid
import re
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class ShadowAPIAnalyzer:
    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # Check for multiple coexisting major versions (e.g. /v1 and /v2)
        version_prefixes = set()
        for ep in endpoints:
            match = re.search(r'/(v[0-9]+)/', ep.path.lower())
            if match:
                version_prefixes.add(match.group(1))

        if len(version_prefixes) > 1:
            sorted_versions = sorted(list(version_prefixes))
            findings.append(SecurityFinding(
                id=str(uuid.uuid4()),
                rule_id="API-VER-002",
                title="Multiple Legacy API Versions Active (Shadow / Zombie API Risk)",
                category="API Inventory & Zombie APIs",
                severity="MEDIUM",
                confidence=0.90,
                endpoint="Global API Inventory",
                method="GLOBAL",
                description=f"The API specification contains multiple major version endpoints ({', '.join(sorted_versions)}) running concurrently. Older API versions frequently lack newly implemented security patches and rate limits.",
                evidence=f"Active endpoints span distinct version prefixes: {sorted_versions}.",
                impact="Attackers target older, unmaintained API versions (Zombie APIs) where security mitigations, input sanitization, and updated authentication schemes were never backported.",
                recommendation="Formulate a formal API deprecation policy. Declare 'Sunset' and 'Deprecation' response headers on legacy endpoints and enforce an end-of-life decommission schedule.",
                fix_code_example="""// In Express.js / API Gateway Header
res.set({
  'Deprecation': '@1717113600',
  'Sunset': 'Wed, 31 Dec 2026 23:59:59 GMT',
  'Link': '<https://api.example.com/v2/docs>; rel="successor-version"'
});""",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                    "https://cwe.mitre.org/data/definitions/1059.html"
                ],
                cwe_id="CWE-1059",
                owasp_category="API9:2023 Improper Inventory Management"
            ))

        # Check deprecated endpoints
        for ep in endpoints:
            if ep.is_deprecated:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-VER-001",
                    title="Deprecated Endpoint Maintained in Active Specification",
                    category="API Inventory & Zombie APIs",
                    severity="LOW",
                    confidence=0.95,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Endpoint '{ep.method} {ep.path}' is flagged with 'deprecated: true' but remains active and callable.",
                    evidence=f"OpenAPI flag 'deprecated: true' on {ep.method} {ep.path}.",
                    impact="Deprecated endpoints represent technical debt and potential attack surfaces that are rarely monitored or updated with modern security controls.",
                    recommendation="Schedule decommission for this deprecated endpoint and notify consuming clients via Sunset HTTP headers.",
                    fix_code_example=f"""# Migrate clients to current endpoint and remove:
# {ep.method} {ep.path} (deprecated)""",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                    cwe_id="CWE-1059",
                    owasp_category="API9:2023 Improper Inventory Management"
                ))

            # Check internal / debug / test routes
            path_lower = ep.path.lower()
            if any(dbg in path_lower for dbg in ["/test/", "/debug/", "/mock/", "/demo/", "/temp/", "/staging/"]):
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-VER-003",
                    title="Internal / Test / Debug Path Exposed in Specification",
                    category="API Inventory & Zombie APIs",
                    severity="HIGH",
                    confidence=0.92,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Endpoint '{ep.method} {ep.path}' appears to be a test, staging, or debug route accidentally exposed in the production API specification.",
                    evidence=f"Debug / staging keyword identified in route path: {ep.path}.",
                    impact="Test routes often bypass authentication, mock payment responses, or expose test database instances to public discovery.",
                    recommendation="Remove internal testing and debug routes from production API specifications and gateway routes.",
                    fix_code_example="""// Ensure test routers are only mounted in development:
if (process.env.NODE_ENV !== 'production') {
  app.use('/test', testRouter);
}""",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
                    cwe_id="CWE-489",
                    owasp_category="API9:2023 Improper Inventory Management"
                ))

        return findings
