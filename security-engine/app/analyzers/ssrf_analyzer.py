import uuid
import re
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class SSRFAnalyzer:
    SSRF_PARAMETER_KEYWORDS = [
        "url", "callback", "redirect", "webhook", "target", "endpoint",
        "resourceurl", "imageurl", "fetchurl", "ping", "feed", "uri", "destination", "site"
    ]

    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            ssrf_params = []

            # Check query/path parameters
            for p in ep.parameters:
                p_clean = re.sub(r'[^a-zA-Z0-9]', '', p.name.lower())
                if any(kw == p_clean or kw in p_clean for kw in SSRFAnalyzer.SSRF_PARAMETER_KEYWORDS):
                    ssrf_params.append(p.name)

            # Check request body properties
            if ep.request_body and ep.request_body.schema_details:
                props = ep.request_body.schema_details.get("properties", {})
                for prop_name in props.keys():
                    prop_clean = re.sub(r'[^a-zA-Z0-9]', '', prop_name.lower())
                    if any(kw == prop_clean or kw in prop_clean for kw in SSRFAnalyzer.SSRF_PARAMETER_KEYWORDS):
                        ssrf_params.append(prop_name)

            # Check path keyword (e.g. /fetch-url, /proxy, /webhook)
            path_lower = ep.path.lower()
            path_matches_ssrf = any(kw in path_lower for kw in ["fetch", "proxy", "webhook", "callback", "forward"])

            if ssrf_params or path_matches_ssrf:
                param_evidence = f"Parameters identified: {ssrf_params}" if ssrf_params else f"Route pattern '{ep.path}' suggests outbound relay."
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-SSRF-001",
                    title="Potential Server-Side Request Forgery (SSRF) Risk",
                    category="Server-Side Request Forgery",
                    severity="HIGH",
                    confidence=0.86,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Endpoint '{ep.method} {ep.path}' accepts external URL/callback parameters or acts as an outbound fetcher ({param_evidence}). The API specification indicates outbound HTTP connection capabilities.",
                    evidence=f"{param_evidence}. Outbound URL handling detected in API contract.",
                    impact="If the server fetches remote resources without strict IP allowlisting and loopback blocking, an attacker can coerce the backend to probe internal microservices, cloud metadata APIs (169.254.169.254), or local loopback interfaces (127.0.0.1). Note: Runtime network restrictions are required to confirm exploitability.",
                    recommendation="Validate and parse all user-supplied URLs against a strict whitelist of allowed domains and protocols. Prohibit local loopback (127.0.0.1, ::1), private RFC1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and cloud metadata IP addresses. Run outbound fetchers in an isolated network sandbox.",
                    fix_code_example="""// Node.js SSRF Prevention Utility
import ip from 'ip';
import dns from 'dns/promises';

async function validateOutboundUrl(targetUrl) {
  const parsed = new URL(targetUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Invalid protocol');
  }
  
  const { address } = await dns.lookup(parsed.hostname);
  if (ip.isPrivate(address) || ip.isLoopback(address) || address === '169.254.169.254') {
    throw new Error('SSRF Blocked: Destination IP is restricted');
  }
  return true;
}""",
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                        "https://cwe.mitre.org/data/definitions/918.html"
                    ],
                    cwe_id="CWE-918",
                    owasp_category="API7:2023 Server Side Request Forgery"
                ))

        return findings
