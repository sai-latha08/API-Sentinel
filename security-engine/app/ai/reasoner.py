import os
from typing import List, Dict, Any, Optional
from app.schemas.models import (
    SecurityFinding, EndpointDefinition, AskSentinelResponse
)

class AIReasoner:
    @staticmethod
    def generate_executive_summary(
        api_title: str,
        risk_score: int,
        risk_level: str,
        findings: List[SecurityFinding],
        endpoints: List[EndpointDefinition]
    ) -> str:
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")
        total_ep = len(endpoints)
        
        categories = list(set(f.category for f in findings))
        top_cats = ", ".join(categories[:3]) if categories else "general hygiene"

        summary_parts = [
            f"### Executive Security Posture Assessment for **{api_title}**\n\n",
            f"API Sentinel completed an automated security posture and abuse analysis across **{total_ep} endpoints**, uncovering **{len(findings)} total security observations** resulting in an overall **API Security Risk Score of {risk_score}/100 ({risk_level})**.\n\n"
        ]

        if crit_count > 0 or high_count > 0:
            summary_parts.append(
                f"**Critical Areas of Immediate Concern:**\n"
                f"- **{crit_count} Critical** and **{high_count} High** severity risks were detected, primarily concentrated in **{top_cats}**.\n"
                f"- Primary threat exposure includes direct object identifier exposure (BOLA/IDOR risk), unauthenticated administrative control paths, or credential/PII exposure in response contracts.\n\n"
            )
        else:
            summary_parts.append(
                f"**Baseline Posture:**\n"
                f"- The specification demonstrates a solid baseline without immediate critical authentication gaps. However, {med_count} medium-priority areas (such as rate limiting documentation and input bounds) should be addressed to prevent abuse.\n\n"
            )

        summary_parts.append(
            f"**Strategic Remediation Recommendation:**\n"
            f"1. **Enforce Zero-Trust Authorization:** Apply server-side object ownership validation for all endpoints accepting direct path IDs.\n"
            f"2. **Implement Gateway-Level Rate Limiting:** Enforce token-bucket throttling on sensitive authentication and payment flows.\n"
            f"3. **Sanitize Data Transfer Objects (DTOs):** Ensure response models exclude backend credentials, password hashes, and excessive internal metadata before serialization."
        )

        return "".join(summary_parts)

    @staticmethod
    def generate_prioritized_recommendations(findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        # Group recommendations by rule/category with priority
        recs = []
        rule_map: Dict[str, List[SecurityFinding]] = {}
        for f in findings:
            rule_map.setdefault(f.rule_id, []).append(f)

        priority_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        
        for rule_id, f_list in rule_map.items():
            rep = f_list[0]
            affected_eps = [f.endpoint for f in f_list]
            
            recs.append({
                "ruleId": rule_id,
                "title": rep.title,
                "category": rep.category,
                "severity": rep.severity,
                "affectedCount": len(f_list),
                "affectedEndpoints": affected_eps[:5],
                "action": rep.recommendation,
                "codeExample": rep.fix_code_example,
                "impact": rep.impact,
                "cwe": rep.cwe_id,
                "owasp": rep.owasp_category
            })

        # Sort recommendations by highest severity first
        recs.sort(key=lambda r: priority_order.index(r["severity"]) if r["severity"] in priority_order else 99)
        return recs

    @staticmethod
    def answer_query(
        query: str,
        findings: List[SecurityFinding],
        endpoints: List[EndpointDefinition],
        finding_id: Optional[str] = None,
        endpoint_name: Optional[str] = None
    ) -> AskSentinelResponse:
        q_lower = query.lower()

        # Specific finding context
        target_finding = None
        if finding_id:
            target_finding = next((f for f in findings if f.id == finding_id or f.rule_id == finding_id), None)
        elif endpoint_name:
            target_finding = next((f for f in findings if f.endpoint == endpoint_name), None)

        if target_finding:
            answer = (
                f"### Security Analysis: {target_finding.title} ({target_finding.severity})\n\n"
                f"**Endpoint:** `{target_finding.method} {target_finding.endpoint}`\n\n"
                f"**Why this matters:**\n{target_finding.description}\n\n"
                f"**Evidence from Specification:**\n{target_finding.evidence}\n\n"
                f"**Potential Security Impact:**\n{target_finding.impact}\n\n"
                f"**Remediation Guidance:**\n{target_finding.recommendation}"
            )
            return AskSentinelResponse(
                answer=answer,
                confidence=0.95,
                grounded_evidence=[target_finding.evidence, f"Severity: {target_finding.severity}", f"Category: {target_finding.category}"],
                remediation_suggestion=target_finding.recommendation,
                relevant_rules=[target_finding.rule_id],
                code_snippet=target_finding.fix_code_example
            )

        # Question: Which findings should I fix first? / Priority
        if any(term in q_lower for term in ["fix first", "priority", "most important", "start with"]):
            criticals = [f for f in findings if f.severity == "CRITICAL"]
            highs = [f for f in findings if f.severity == "HIGH"]
            
            answer_lines = ["### Prioritized Remediation Strategy\n\n"]
            evidence = []
            rules = []

            if criticals:
                answer_lines.append(f"**Step 1: Immediate Triage (Critical - {len(criticals)} items)**\n")
                for c in criticals[:3]:
                    answer_lines.append(f"- **[{c.rule_id}] {c.title}** on `{c.endpoint}`: {c.recommendation}\n")
                    evidence.append(f"Critical on {c.endpoint}")
                    rules.append(c.rule_id)
                answer_lines.append("\n")

            if highs:
                answer_lines.append(f"**Step 2: High-Risk Mitigation ({len(highs)} items)**\n")
                for h in highs[:3]:
                    answer_lines.append(f"- **[{h.rule_id}] {h.title}** on `{h.endpoint}`\n")
                    evidence.append(f"High on {h.endpoint}")
                    rules.append(h.rule_id)
                answer_lines.append("\n")

            if not criticals and not highs:
                answer_lines.append("No Critical or High severity findings were discovered in this scan. Focus on medium-priority anti-abuse and rate-limiting definitions.\n")

            return AskSentinelResponse(
                answer="".join(answer_lines),
                confidence=0.92,
                grounded_evidence=evidence[:4],
                remediation_suggestion="Triage critical credential and access control gaps prior to public deployment.",
                relevant_rules=rules[:4],
                code_snippet=criticals[0].fix_code_example if criticals else None
            )

        # Question: How do I fix BOLA? / IDOR
        if "bola" in q_lower or "idor" in q_lower or "broken object" in q_lower:
            bola_findings = [f for f in findings if f.category == "Authorization" or "BOLA" in f.rule_id]
            eps = [f.endpoint for f in bola_findings]
            answer = (
                "### How to Prevent Broken Object Level Authorization (BOLA / IDOR)\n\n"
                "BOLA occurs when an API endpoint accepts a direct object identifier (e.g. `/orders/{orderId}`) without verifying that the requesting user has legitimate ownership or permission to access that specific entity.\n\n"
                "**Core Remediation Principles:**\n"
                "1. **Never trust client-supplied IDs alone:** Always validate that `resource.userId === authenticatedUser.id` on the server.\n"
                "2. **Scope Database Queries:** Incorporate the user's authenticated tenant/account ID directly in SQL or ORM queries (e.g. `SELECT * FROM orders WHERE id = :orderId AND user_id = :currentUserId`).\n"
                "3. **Use Random Opaque IDs:** Use UUIDv4 or ULID instead of predictable sequential integer IDs (1, 2, 3...).\n\n"
                f"**Affected Endpoints in your scan:** {', '.join(eps[:4]) if eps else 'None identified in current scan.'}"
            )
            code_example = """// Node.js Express Secure Ownership Verification
router.get('/orders/:orderId', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const currentUserId = req.user.id; // From verified JWT

  const order = await Order.findOne({ _id: orderId, userId: currentUserId });
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }
  res.json(order);
});"""
            return AskSentinelResponse(
                answer=answer,
                confidence=0.96,
                grounded_evidence=[f"Found {len(bola_findings)} potential BOLA endpoint(s)"],
                remediation_suggestion="Enforce database-level scoping with authenticated user ID token claims.",
                relevant_rules=["API-BOLA-001", "API-BOLA-002"],
                code_snippet=code_example
            )

        # Question: Difference between Authentication vs Authorization
        if "difference" in q_lower and ("auth" in q_lower or "authorization" in q_lower):
            answer = (
                "### Authentication vs. Authorization in API Security\n\n"
                "| Concept | Question Answered | Mechanism in APIs | Common Vulnerability |\n"
                "| :--- | :--- | :--- | :--- |\n"
                "| **Authentication (AuthN)** | *'Who are you?'* | JWT, OAuth2, API Keys, Passwords | API2:2023 Broken Authentication (Missing JWT verification, weak credentials) |\n"
                "| **Authorization (AuthZ)** | *'What are you permitted to do?'* | RBAC, ABAC, Scopes, Ownership checks | API1:2023 BOLA & API5:2023 BFLA (Regular user accessing admin or other user's record) |\n\n"
                "**Key Takeaway:** An API endpoint can have perfect authentication (a valid verified JWT token) and still suffer from catastrophic authorization vulnerabilities if any authenticated user can read another user's private records."
            )
            return AskSentinelResponse(
                answer=answer,
                confidence=0.98,
                grounded_evidence=["Conceptual API Security Principles", "OWASP API Security Top 10 (2023)"],
                remediation_suggestion="Implement distinct middleware layers for identity verification (AuthN) followed by permission/ownership verification (AuthZ).",
                relevant_rules=["API-AUTH-001", "API-BOLA-001", "API-BFLA-001"],
                code_snippet=None
            )

        # Question: Why is this API considered high/critical risk?
        if any(term in q_lower for term in ["why", "high risk", "score", "calculate", "risk score"]):
            crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
            high_count = sum(1 for f in findings if f.severity == "HIGH")
            top_reasons = []
            for f in findings:
                if f.severity in ["CRITICAL", "HIGH"] and f.title not in top_reasons:
                    top_reasons.append(f"- **{f.title}** on `{f.endpoint}`: {f.impact}")

            answer = (
                f"### Risk Score Breakdown & Explanation\n\n"
                f"API Sentinel calculated the security score based on **{crit_count} Critical** and **{high_count} High** severity findings detected across your specification:\n\n"
                + "\n".join(top_reasons[:5]) +
                f"\n\n**Calculation Multipliers:**\n"
                f"- High-severity penalties applied for unauthenticated admin paths and direct object ID exposures.\n"
                f"- Route asset sensitivity multiplier based on proportion of financial, authentication, and administrative endpoints."
            )
            return AskSentinelResponse(
                answer=answer,
                confidence=0.94,
                grounded_evidence=[f"Critical count: {crit_count}", f"High count: {high_count}"],
                remediation_suggestion="Remediate critical findings to rapidly improve the security posture score.",
                relevant_rules=[f.rule_id for f in findings if f.severity in ["CRITICAL", "HIGH"]][:4],
                code_snippet=None
            )

        # General context-grounded fallback
        matched_findings = [f for f in findings if any(w in f.title.lower() or w in f.description.lower() for w in q_lower.split())]
        if matched_findings:
            f = matched_findings[0]
            answer = (
                f"### Relevant Finding: {f.title} ({f.severity})\n\n"
                f"**Endpoint:** `{f.method} {f.endpoint}`\n\n"
                f"{f.description}\n\n"
                f"**Impact:** {f.impact}\n\n"
                f"**Action:** {f.recommendation}"
            )
            return AskSentinelResponse(
                answer=answer,
                confidence=0.85,
                grounded_evidence=[f.evidence],
                remediation_suggestion=f.recommendation,
                relevant_rules=[f.rule_id],
                code_snippet=f.fix_code_example
            )

        # Safe fallback when insufficient evidence
        return AskSentinelResponse(
            answer="Based on the analyzed API specification, there is insufficient evidence to provide a conclusive determination on this specific query. Please consult the Finding Explorer or verify backend runtime implementations.",
            confidence=0.70,
            grounded_evidence=["Insufficient specification evidence"],
            remediation_suggestion="Review API contract documentation and perform dynamic runtime testing.",
            relevant_rules=[],
            code_snippet=None
        )
