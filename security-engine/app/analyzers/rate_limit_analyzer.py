import uuid
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class RateLimitAnalyzer:
    ABUSE_PRONE_ENDPOINTS = [
        "login", "signin", "register", "signup", "auth", "token",
        "forgot-password", "reset-password", "otp", "verify",
        "send-sms", "send-email", "2fa", "mfa", "coupon", "redeem",
        "voucher", "payment", "checkout", "search", "export", "report", "bulk"
    ]

    RATE_LIMIT_HEADERS = [
        "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
        "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "retry-after"
    ]

    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            path_lower = ep.path.lower()
            matched_abuse_keywords = [w for w in RateLimitAnalyzer.ABUSE_PRONE_ENDPOINTS if w in path_lower]

            if matched_abuse_keywords:
                kw_str = ", ".join(matched_abuse_keywords)
                
                # Inspect response headers across all defined responses for rate limit headers
                has_rate_limit_header = False
                documented_headers = []
                for resp in ep.responses:
                    for h in resp.headers:
                        documented_headers.append(h)
                        if h.lower() in RateLimitAnalyzer.RATE_LIMIT_HEADERS:
                            has_rate_limit_header = True

                # Check endpoint description / summary for mentions of rate limits
                full_text = f"{ep.summary or ''} {ep.description or ''}".lower()
                has_text_mention = any(term in full_text for term in ["rate limit", "throttl", "requests per", "req/min", "rpm", "burst"])

                if not has_rate_limit_header and not has_text_mention:
                    # Critical/High auth flow vs general expensive search
                    is_auth = any(w in path_lower for w in ["login", "signin", "register", "password", "otp", "2fa", "mfa", "token"])
                    is_financial = any(w in path_lower for w in ["payment", "checkout", "coupon", "redeem", "voucher"])
                    
                    if is_auth or is_financial:
                        severity = "HIGH"
                        context_type = "Authentication / Sensitive Transaction Flow"
                        abuse_scenario = "Automated brute-force credential stuffing, password spray, OTP flooding, or financial racing"
                    else:
                        severity = "MEDIUM"
                        context_type = "High-Cost / Computationally Heavy Operation"
                        abuse_scenario = "Denial of Service (DoS) and excessive database query consumption"

                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        rule_id="API-RATE-001",
                        title="Rate Limiting & Anti-Abuse Controls Not Documented",
                        category="Rate Limiting & Abuse Prevention",
                        severity=severity,
                        confidence=0.85,
                        endpoint=ep.path,
                        method=ep.method,
                        description=f"Endpoint '{ep.method} {ep.path}' represents an {context_type} (keywords: {kw_str}), but rate limiting, throttling policies, and standard rate-limit headers (X-RateLimit-Limit, Retry-After) are not documented in the API specification.",
                        evidence=f"No rate-limit headers (X-RateLimit-*, Retry-After) or throttling definitions declared. Matched abuse keywords: [{kw_str}].",
                        impact=f"Without server-side rate limiting, this endpoint is vulnerable to: {abuse_scenario}.",
                        recommendation="Implement IP and token-based rate limiting (e.g. Redis sliding window or token bucket algorithm). Declare standard RateLimit and 429 Too Many Requests response headers in the API contract.",
                        fix_code_example="""// Express.js Rate Limiter Example (express-rate-limit)
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 failed attempts per window
  standardHeaders: true, // Return standard RateLimit-* headers
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again after 15 minutes' }
});

router.post('/api/login', authLimiter, loginHandler);""",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                            "https://cwe.mitre.org/data/definitions/770.html"
                        ],
                        cwe_id="CWE-770",
                        owasp_category="API4:2023 Unrestricted Resource Consumption"
                    ))

        return findings
