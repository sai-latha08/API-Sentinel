import uuid
import re
from typing import List, Dict, Any, Tuple
from app.schemas.models import EndpointDefinition, SecurityFinding

class SensitiveDataAnalyzer:
    CRITICAL_SECRET_FIELDS = [
        "passwordhash", "password_hash", "passwd_hash", "privatekey", "private_key",
        "secretkey", "secret_key", "client_secret", "clientsecret", "db_password",
        "refreshtoken", "refresh_token", "masterkey", "encryption_key"
    ]
    
    HIGH_PII_FIELDS = [
        "ssn", "socialsecurity", "aadhaar", "passport", "creditcard", "credit_card",
        "cardnumber", "cvv", "cvc", "bankaccount", "bank_account", "routingnumber",
        "taxid", "national_id"
    ]
    
    MODERATE_PII_FIELDS = [
        "password", "accesstoken", "access_token", "apikey", "api_key", "token",
        "phone", "phonenumber", "telephone", "address", "dateofbirth", "dob",
        "salary", "income", "medical", "diagnosis"
    ]

    @staticmethod
    def _extract_property_names(schema: Dict[str, Any], depth: int = 0) -> List[str]:
        if depth > 5 or not isinstance(schema, dict):
            return []
        props = []
        if "properties" in schema and isinstance(schema["properties"], dict):
            for k, v in schema["properties"].items():
                props.append(k)
                if isinstance(v, dict):
                    props.extend(SensitiveDataAnalyzer._extract_property_names(v, depth + 1))
        if "items" in schema and isinstance(schema["items"], dict):
            props.extend(SensitiveDataAnalyzer._extract_property_names(schema["items"], depth + 1))
        return props

    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            # 1. Query parameter sensitive data checks
            for param in ep.parameters:
                if param.in_location == "query":
                    p_lower = re.sub(r'[^a-zA-Z0-9]', '', param.name.lower())
                    if any(secret in p_lower for secret in ["password", "token", "apikey", "secret", "auth", "credential", "private"]):
                        findings.append(SecurityFinding(
                            id=str(uuid.uuid4()),
                            rule_id="API-DATA-003",
                            title="Sensitive Information Transmitted in Query Parameters",
                            category="Sensitive Data Exposure",
                            severity="HIGH",
                            confidence=0.92,
                            endpoint=ep.path,
                            method=ep.method,
                            description=f"Query parameter '{param.name}' in '{ep.method} {ep.path}' appears to accept sensitive credentials or tokens in the URL string.",
                            evidence=f"Parameter '{param.name}' is in 'query'. URLs are routinely stored in browser histories, proxy logs, CDN logs, and Referer headers.",
                            impact="Secrets passed via query strings are cached in plain text across web server logs, load balancers, and third-party Referer destinations.",
                            recommendation="Pass authentication credentials, tokens, and secrets via standard HTTP headers (e.g. 'Authorization: Bearer <token>') or inside the encrypted HTTPS request payload.",
                            fix_code_example="""// Insecure:
GET /api/v1/data?apiKey=secret_xyz123

// Secure:
GET /api/v1/data
Authorization: Bearer secret_xyz123""",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#parameters-in-uri"],
                            cwe_id="CWE-598",
                            owasp_category="API3:2023 Broken Object Property Level Authorization"
                        ))

            # 2. Response Schema analysis for data exposure
            for resp in ep.responses:
                # We analyze successful or data-returning response codes (200, 201, 200-range, default)
                if resp.status_code.startswith("2") or resp.status_code == "default":
                    if resp.schema_details:
                        prop_names = SensitiveDataAnalyzer._extract_property_names(resp.schema_details)
                        
                        # Check critical secrets
                        critical_exposed = []
                        for prop in prop_names:
                            clean_prop = re.sub(r'[^a-zA-Z0-9]', '', prop.lower())
                            if any(crit == clean_prop or crit in clean_prop for crit in SensitiveDataAnalyzer.CRITICAL_SECRET_FIELDS):
                                critical_exposed.append(prop)

                        if critical_exposed:
                            findings.append(SecurityFinding(
                                id=str(uuid.uuid4()),
                                rule_id="API-DATA-001",
                                title="Critical Credential / Secret Hash Exposed in Response Schema",
                                category="Sensitive Data Exposure",
                                severity="CRITICAL",
                                confidence=0.96,
                                endpoint=ep.path,
                                method=ep.method,
                                description=f"Response schema for status {resp.status_code} on '{ep.method} {ep.path}' declares fields containing sensitive secrets or password hashes: [{', '.join(critical_exposed)}].",
                                evidence=f"Schema properties matched: {critical_exposed} in HTTP {resp.status_code} response model.",
                                impact="Exposing password hashes, private keys, or refresh tokens allows attackers to perform offline cracking, impersonate users, or maintain unauthorized access.",
                                recommendation="Explicitly transform and sanitize response Data Transfer Objects (DTOs). Exclude password hashes, cryptographic keys, and master secrets before serialization.",
                                fix_code_example="""// Use a strict DTO or serializer that strips sensitive fields
function toUserDTO(user) {
  const { passwordHash, privateKey, secretKey, ...safeUser } = user.toObject();
  return safeUser;
}

res.json(toUserDTO(user));""",
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                                    "https://cwe.mitre.org/data/definitions/200.html"
                                ],
                                cwe_id="CWE-200",
                                owasp_category="API3:2023 Broken Object Property Level Authorization"
                            ))

                        # Check high PII fields
                        pii_exposed = []
                        for prop in prop_names:
                            clean_prop = re.sub(r'[^a-zA-Z0-9]', '', prop.lower())
                            if any(pii == clean_prop or pii in clean_prop for pii in SensitiveDataAnalyzer.HIGH_PII_FIELDS):
                                pii_exposed.append(prop)

                        if pii_exposed:
                            findings.append(SecurityFinding(
                                id=str(uuid.uuid4()),
                                rule_id="API-DATA-002",
                                title="High-Sensitivity PII / Financial Data in Response Schema",
                                category="Sensitive Data Exposure",
                                severity="HIGH",
                                confidence=0.90,
                                endpoint=ep.path,
                                method=ep.method,
                                description=f"Response schema for status {resp.status_code} on '{ep.method} {ep.path}' returns high-sensitivity PII or financial identifier(s): [{', '.join(pii_exposed)}].",
                                evidence=f"Schema properties identified: {pii_exposed} in response model.",
                                impact="Violation of privacy regulations (GDPR, HIPAA, PCI-DSS) and heightened risk of identity theft or credit card fraud upon data leaks.",
                                recommendation="Mask or truncate sensitive PII fields (e.g. show only last 4 digits of card/SSN) and ensure strict tokenized access.",
                                fix_code_example="""// Mask Credit Card / SSN in response
function maskCard(cardNumber) {
  return `****-****-****-${cardNumber.slice(-4)}`;
}""",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html"],
                                cwe_id="CWE-359",
                                owasp_category="API3:2023 Broken Object Property Level Authorization"
                            ))

                        # Check moderate PII on unauthenticated endpoints
                        if not ep.is_authenticated:
                            mod_pii = []
                            for prop in prop_names:
                                clean_prop = re.sub(r'[^a-zA-Z0-9]', '', prop.lower())
                                if clean_prop in ["email", "phone", "phonenumber", "address", "dateofbirth", "dob"]:
                                    mod_pii.append(prop)
                            if mod_pii:
                                findings.append(SecurityFinding(
                                    id=str(uuid.uuid4()),
                                    rule_id="API-DATA-004",
                                    title="Personal Contact Information Exposed on Unauthenticated Route",
                                    category="Sensitive Data Exposure",
                                    severity="LOW",
                                    confidence=0.80,
                                    endpoint=ep.path,
                                    method=ep.method,
                                    description=f"Endpoint '{ep.method} {ep.path}' does not require authentication and returns personal contact fields: [{', '.join(mod_pii)}].",
                                    evidence=f"Public route with response schema containing properties: {mod_pii}.",
                                    impact="Enables automated scraping for phishing campaigns, spam targeting, and OSINT profiling.",
                                    recommendation="Authenticate profile routes or redact personal contact data from public directory endpoints.",
                                    fix_code_example="""// Redact email & phone for unauthenticated callers
if (!req.user) {
  delete userProfile.email;
  delete userProfile.phone;
}""",
                                    references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                                    cwe_id="CWE-200",
                                    owasp_category="API3:2023 Broken Object Property Level Authorization"
                                ))

        return findings
