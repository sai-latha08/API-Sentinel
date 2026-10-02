import uuid
import re
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding
from app.analyzers.sensitive_data_analyzer import SensitiveDataAnalyzer

class ExcessiveDataAnalyzer:
    INTERNAL_FIELD_KEYWORDS = [
        "internalcost", "internal_cost", "suppliersecret", "supplier_secret",
        "adminnotes", "admin_notes", "internalkey", "internal_id", "db_version",
        "createdbyip", "created_by_ip", "lastloginip", "server_timestamp",
        "execution_time_ms", "sql_query", "debug_info", "raw_payload"
    ]

    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            for resp in ep.responses:
                if resp.status_code.startswith("2") or resp.status_code == "default":
                    if resp.schema_details:
                        props = SensitiveDataAnalyzer._extract_property_names(resp.schema_details)
                        
                        matched_internal = []
                        for p in props:
                            clean_p = re.sub(r'[^a-zA-Z0-9]', '', p.lower())
                            if any(int_kw in clean_p for int_kw in ExcessiveDataAnalyzer.INTERNAL_FIELD_KEYWORDS):
                                matched_internal.append(p)

                        if matched_internal:
                            findings.append(SecurityFinding(
                                id=str(uuid.uuid4()),
                                rule_id="API-EXCESS-001",
                                title="Potential Excessive Data Exposure / Internal Metadata",
                                category="Excessive Data Exposure",
                                severity="MEDIUM",
                                confidence=0.88,
                                endpoint=ep.path,
                                method=ep.method,
                                description=f"Endpoint '{ep.method} {ep.path}' exposes internal backend metadata or proprietary business fields in its response schema: [{', '.join(matched_internal)}].",
                                evidence=f"Schema properties matched: {matched_internal} on response status {resp.status_code}.",
                                impact="Exposes internal system topology, commercial supplier terms, or administrative annotations to client applications and untrusted third parties.",
                                recommendation="Do not rely on the client frontend to filter out sensitive or internal properties. Filter responses on the server using specialized view DTOs.",
                                fix_code_example="""// In Java Spring / Jackson:
public class ProductResponseDTO {
    private String id;
    private String name;
    private BigDecimal publicPrice;
    // Exclude internalCost, supplierSecret, adminNotes from DTO
}""",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                                cwe_id="CWE-213",
                                owasp_category="API3:2023 Broken Object Property Level Authorization"
                            ))

                        # Check generic unconstrained object responses (e.g. type: object with no properties defined)
                        schema_type = resp.schema_details.get("type")
                        schema_props = resp.schema_details.get("properties", {})
                        if schema_type == "object" and not schema_props and not resp.schema_details.get("allOf"):
                            findings.append(SecurityFinding(
                                id=str(uuid.uuid4()),
                                rule_id="API-EXCESS-002",
                                title="Unconstrained Generic Object Response Schema",
                                category="Excessive Data Exposure",
                                severity="LOW",
                                confidence=0.75,
                                endpoint=ep.path,
                                method=ep.method,
                                description=f"Response schema for '{ep.method} {ep.path}' is declared as an unconstrained generic object ('type: object' with no schema definition).",
                                evidence=f"Response {resp.status_code} schema defines type 'object' without explicit property boundaries.",
                                impact="Returning arbitrary or unmapped database documents directly risks dumping unexpected private fields, sensitive associations, and internal database metadata.",
                                recommendation="Define explicit schema models and property definitions for all API responses.",
                                fix_code_example="""# OpenAPI Schema Definition
responses:
  '200':
    description: Success
    content:
      application/json:
        schema:
          type: object
          required: [id, status]
          properties:
            id:
              type: string
            status:
              type: string""",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                                cwe_id="CWE-200",
                                owasp_category="API3:2023 Broken Object Property Level Authorization"
                            ))

        return findings
