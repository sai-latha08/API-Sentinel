import uuid
import re
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class BOLAAnalyzer:
    ID_PATTERNS = re.compile(r'\{([a-zA-Z0-9_-]*(?:id|account|order|user|doc|file|org|uuid|tenant|invoice|payment|subscription)[a-zA-Z0-9_-]*)\}', re.IGNORECASE)
    
    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            path_matches = BOLAAnalyzer.ID_PATTERNS.findall(ep.path)
            
            # Check path parameters or query parameters accepting direct IDs
            id_params = []
            for p in ep.parameters:
                if p.in_location in ["path", "query"]:
                    p_lower = p.name.lower()
                    if any(key in p_lower for key in ["id", "account", "order", "user", "doc", "invoice", "payment", "customer"]):
                        id_params.append(p)

            if path_matches or id_params:
                matched_names = path_matches if path_matches else [p.name for p in id_params]
                param_str = ", ".join(matched_names)

                # Differentiate severity based on method and context
                if ep.method in ["DELETE", "PUT", "PATCH"]:
                    severity = "HIGH"
                    action_desc = f"destructive/modifying operation ({ep.method})"
                elif ep.method == "GET":
                    severity = "HIGH" if any(w in ep.path.lower() for w in ["payment", "order", "document", "account", "invoice"]) else "MEDIUM"
                    action_desc = "read access operation (GET)"
                else:
                    severity = "MEDIUM"
                    action_desc = f"state creation/mutation ({ep.method})"

                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-BOLA-001",
                    title="Potential Broken Object Level Authorization (BOLA / IDOR)",
                    category="Authorization",
                    severity=severity,
                    confidence=0.85,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Object identifier parameter(s) [{param_str}] are accepted directly in endpoint '{ep.method} {ep.path}' for a {action_desc}. The API specification does not provide evidence that access is restricted to resources owned by the authenticated user.",
                    evidence=f"Path template contains direct object identifier(s): {matched_names}. Method: {ep.method}.",
                    impact="If the application backend fails to validate that the requested object ID belongs to the caller's session token, an attacker can manipulate IDs to view, modify, or delete other users' private data.",
                    recommendation="Enforce server-side object ownership verification in every controller. Ensure queries filter by both the object ID AND the authenticated user's ID (e.g., WHERE id = :id AND user_id = :currentUser.id). Prefer non-enumerable UUIDv4 over sequential IDs.",
                    fix_code_example="""// Secure Node.js/Express Controller Example
router.get('/orders/:orderId', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const currentUserId = req.user.id; // From verified JWT

  // MUST scope by both object ID and authenticated user ID:
  const order = await Order.findOne({ _id: orderId, userId: currentUserId });
  if (!order) {
    return res.status(404).json({ error: 'Order not found or unauthorized' });
  }
  res.json(order);
});""",
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                        "https://cwe.mitre.org/data/definitions/639.html"
                    ],
                    cwe_id="CWE-639",
                    owasp_category="API1:2023 Broken Object Level Authorization"
                ))

                # Check if parameter type is integer (sequential numeric ID risk)
                for p in ep.parameters:
                    if p.name in matched_names and p.param_type in ["integer", "int32", "int64"]:
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4()),
                            rule_id="API-BOLA-002",
                            title="Potential Predictable Sequential Resource Identifier",
                            category="Authorization",
                            severity="LOW",
                            confidence=0.82,
                            endpoint=ep.path,
                            method=ep.method,
                            description=f"Parameter '{p.name}' is defined as an integer type in '{ep.method} {ep.path}'. Sequential integer identifiers make enumeration, scraping, and automated IDOR attacks trivial.",
                            evidence=f"Parameter '{p.name}' schema type is integer ({p.format or 'default'}).",
                            impact="Attackers can sequentially iterate through 1..N to map and harvest all resource records across the organization.",
                            recommendation="Replace predictable integer auto-increments with cryptographically random UUID v4, ULID, or opaque token identifiers.",
                            fix_code_example="""# OpenAPI Schema Update
parameters:
  - name: orderId
    in: path
    required: true
    schema:
      type: string
      format: uuid
      example: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d" """,
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_References_Prevention_Cheat_Sheet.html"],
                            cwe_id="CWE-330",
                            owasp_category="API1:2023 Broken Object Level Authorization"
                        ))

        return findings
