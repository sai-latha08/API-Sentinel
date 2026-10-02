import pytest
from app.parsers.parser_factory import SpecParserFactory
from app.parsers.openapi_parser import OpenAPIParser
from app.analyzers.auth_analyzer import AuthAnalyzer
from app.analyzers.bola_analyzer import BOLAAnalyzer
from app.analyzers.bfla_analyzer import BFLAAnalyzer
from app.analyzers.sensitive_data_analyzer import SensitiveDataAnalyzer
from app.analyzers.rate_limit_analyzer import RateLimitAnalyzer
from app.analyzers.ssrf_analyzer import SSRFAnalyzer
from app.analyzers.file_upload_analyzer import FileUploadAnalyzer
from app.scoring.risk_calculator import RiskCalculator

SAMPLE_VULN_SPEC = """
openapi: 3.0.3
info:
  title: Test Vulnerable API
  version: 1.0.0
servers:
  - url: http://insecure-api.internal/v1
paths:
  /admin/users:
    get:
      summary: Admin user list
      responses:
        '200':
          description: List of users
          content:
            application/json:
              schema:
                type: object
                properties:
                  users:
                    type: array
                    items:
                      type: object
                      properties:
                        id:
                          type: integer
                        email:
                          type: string
                        passwordHash:
                          type: string
  /orders/{orderId}:
    get:
      summary: Get order by ID
      parameters:
        - name: orderId
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: Order details
    delete:
      summary: Delete order
      parameters:
        - name: orderId
          in: path
          required: true
          schema:
            type: integer
      responses:
        '204':
          description: Order deleted
  /api/login:
    post:
      summary: User login
      responses:
        '200':
          description: JWT token
  /api/fetch-url:
    post:
      summary: Fetch external site
      parameters:
        - name: webhookUrl
          in: query
          schema:
            type: string
      responses:
        '200':
          description: Fetched result
  /api/upload:
    post:
      summary: Upload file
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                file:
                  type: string
                  format: binary
      responses:
        '200':
          description: File uploaded
"""

def test_openapi_parser():
    meta, endpoints = SpecParserFactory.parse_spec(SAMPLE_VULN_SPEC)
    assert meta["title"] == "Test Vulnerable API"
    assert len(endpoints) >= 5

def test_auth_analyzer():
    meta, endpoints = SpecParserFactory.parse_spec(SAMPLE_VULN_SPEC)
    findings = AuthAnalyzer.analyze(meta, endpoints)
    rule_ids = [f.rule_id for f in findings]
    # Should detect unauthenticated admin endpoint
    assert "API-AUTH-002" in rule_ids or "API-AUTH-001" in rule_ids

def test_bola_analyzer():
    meta, endpoints = SpecParserFactory.parse_spec(SAMPLE_VULN_SPEC)
    findings = BOLAAnalyzer.analyze(meta, endpoints)
    rule_ids = [f.rule_id for f in findings]
    assert "API-BOLA-001" in rule_ids

def test_sensitive_data_analyzer():
    meta, endpoints = SpecParserFactory.parse_spec(SAMPLE_VULN_SPEC)
    findings = SensitiveDataAnalyzer.analyze(meta, endpoints)
    rule_ids = [f.rule_id for f in findings]
    assert "API-DATA-001" in rule_ids  # passwordHash detected

def test_rate_limit_analyzer():
    meta, endpoints = SpecParserFactory.parse_spec(SAMPLE_VULN_SPEC)
    findings = RateLimitAnalyzer.analyze(meta, endpoints)
    rule_ids = [f.rule_id for f in findings]
    assert "API-RATE-001" in rule_ids  # login missing rate limit

def test_ssrf_analyzer():
    meta, endpoints = SpecParserFactory.parse_spec(SAMPLE_VULN_SPEC)
    findings = SSRFAnalyzer.analyze(meta, endpoints)
    rule_ids = [f.rule_id for f in findings]
    assert "API-SSRF-001" in rule_ids  # webhookUrl param

def test_file_upload_analyzer():
    meta, endpoints = SpecParserFactory.parse_spec(SAMPLE_VULN_SPEC)
    findings = FileUploadAnalyzer.analyze(meta, endpoints)
    rule_ids = [f.rule_id for f in findings]
    assert "API-UPLOAD-001" in rule_ids

def test_risk_calculator():
    meta, endpoints = SpecParserFactory.parse_spec(SAMPLE_VULN_SPEC)
    findings = []
    findings.extend(AuthAnalyzer.analyze(meta, endpoints))
    findings.extend(BOLAAnalyzer.analyze(meta, endpoints))
    findings.extend(SensitiveDataAnalyzer.analyze(meta, endpoints))
    score, level, breakdown, cat_scores = RiskCalculator.calculate_score(findings, endpoints)
    assert score > 50  # Should be high risk due to passwordHash + BOLA + unauthenticated admin
    assert level in ["High Risk", "Critical Risk"]
