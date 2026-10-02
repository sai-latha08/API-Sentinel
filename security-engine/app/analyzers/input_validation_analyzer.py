import uuid
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class InputValidationAnalyzer:
    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            # Check request parameters
            unconstrained_params = []
            for p in ep.parameters:
                if p.in_location in ["query", "path"]:
                    details = p.schema_details or {}
                    if p.param_type == "string":
                        # Check if maxLength, pattern, or enum is defined
                        if "maxLength" not in details and "pattern" not in details and "enum" not in details:
                            unconstrained_params.append(p.name)

            if len(unconstrained_params) > 0 and len(unconstrained_params) >= 2:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    rule_id="API-VAL-001",
                    title="Input Validation Constraints Not Documented on Parameters",
                    category="Input Validation & Data Integrity",
                    severity="LOW",
                    confidence=0.78,
                    endpoint=ep.path,
                    method=ep.method,
                    description=f"Parameters [{', '.join(unconstrained_params[:4])}] on '{ep.method} {ep.path}' are defined as generic strings without documented constraints (maxLength, regex pattern, or enum).",
                    evidence=f"Parameters missing schema constraints: {unconstrained_params}.",
                    impact="Without strict boundary limits, parameters may accept arbitrarily large strings leading to buffer/memory overhead, unexpected backend deserialization flaws, or injection risks.",
                    recommendation="Declare explicit maxLength, format, and pattern regular expressions for all incoming parameters.",
                    fix_code_example="""# OpenAPI Schema Definition
parameters:
  - name: username
    in: query
    schema:
      type: string
      minLength: 3
      maxLength: 32
      pattern: '^[a-zA-Z0-9_]+$'""",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"],
                    cwe_id="CWE-20",
                    owasp_category="API8:2023 Security Misconfiguration"
                ))

            # Check request body schema for unbounded arrays / unconstrained properties
            if ep.request_body and ep.request_body.schema_details:
                body_schema = ep.request_body.schema_details
                props = body_schema.get("properties", {})
                
                unbounded_arrays = []
                unconstrained_nums = []
                for prop_name, prop_def in props.items():
                    if isinstance(prop_def, dict):
                        p_type = prop_def.get("type")
                        if p_type == "array" and "maxItems" not in prop_def:
                            unbounded_arrays.append(prop_name)
                        elif p_type in ["integer", "number"] and "maximum" not in prop_def and "minimum" not in prop_def:
                            unconstrained_nums.append(prop_name)

                if unbounded_arrays:
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        rule_id="API-VAL-003",
                        title="Unbounded Array Payload in Request Body (Resource Exhaustion Risk)",
                        category="Input Validation & Data Integrity",
                        severity="LOW",
                        confidence=0.80,
                        endpoint=ep.path,
                        method=ep.method,
                        description=f"Request body on '{ep.method} {ep.path}' accepts array properties [{', '.join(unbounded_arrays)}] without a declared 'maxItems' constraint.",
                        evidence=f"Array properties missing maxItems boundary: {unbounded_arrays}.",
                        impact="Attackers can send thousands or millions of array elements in a single request, triggering backend CPU starvation and Denial of Service (JSON Bomb / ReDoS).",
                        recommendation="Set a strict 'maxItems' limit on all collection/array properties in request contracts.",
                        fix_code_example="""# OpenAPI Schema
properties:
  items:
    type: array
    maxItems: 50
    items:
      type: string
      maxLength: 100""",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
                        cwe_id="CWE-770",
                        owasp_category="API4:2023 Unrestricted Resource Consumption"
                    ))

        return findings
