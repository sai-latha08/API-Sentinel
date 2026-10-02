# 🛡️ API Sentinel

### AI-Assisted API Security Posture & Abuse Analysis Platform

> **"Find API security risks before attackers do."**

API Sentinel is an enterprise-grade cybersecurity platform that performs deep static analysis of API specifications (OpenAPI 3.x, Swagger 2.0, and Postman Collections). It maps attack surfaces, identifies access control gaps (BOLA/IDOR, BFLA), detects sensitive credential exposure, flags missing anti-abuse safeguards, computes multi-factor risk scores, and provides actionable defensive remediation code grounded in actual specification evidence.

---

## 🌟 Key Capabilities

* **Multi-Format Specification Parsing**: Supports OpenAPI 3.0/3.1 (JSON/YAML), Swagger 2.0 (JSON/YAML), and Postman Collections v2.0/v2.1 with full reference (`$ref`) resolution.
* **OWASP API Security Top 10 (2023) Rule Engine**: 26 specialized security analyzers checking for missing authentication, BOLA, BFLA, sensitive credentials, mass assignment, SSRF parameters, unconstrained file uploads, and business logic risks.
* **Transparent Multi-Factor Risk Scoring**: Mathematical 0–100 scoring based on OWASP Risk Rating Methodology incorporating severity weights, confidence levels, and asset sensitivity multipliers.
* **Attack Surface Topology Graph**: Interactive React Flow visual graph showing relationships between the API root, authentication schemes, endpoints, sensitive assets, and threats.
* **Ask Sentinel AI Security Assistant**: Contextual conversational assistant grounded in actual scan evidence providing defensive fixes without generating exploit payloads.
* **Scan Comparison Engine**: Side-by-side version comparison highlighting score delta, fixed findings, new vulnerabilities, and severity shifts.
* **Executive Security Audit Reports**: Printable and downloadable PDF-ready formal security reports.

---

## 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    API SENTINEL FRONTEND                    │
│     React 18 • Vite • Tailwind CSS • React Flow • Recharts  │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / REST API (JWT)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                  NODE.JS EXPRESS BACKEND                    │
│    Auth Middleware • Rate Limiting • Helmet • MongoDB Store │
└──────────────────────────────┬──────────────────────────────┘
                               │ Internal Microservice API
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               PYTHON SECURITY ANALYSIS ENGINE               │
│     FastAPI • OpenAPI/Swagger/Postman Parsers • 26 Rules    │
│    Multi-Factor Scoring Engine • Grounded AI Reasoner       │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 OWASP API Security Rule Catalog

| Rule ID | Title | OWASP Category | Severity |
| :--- | :--- | :--- | :--- |
| **API-AUTH-001** | Missing Declared Authentication Requirement | API2:2023 Broken Authentication | High / Medium |
| **API-AUTH-002** | Unauthenticated Administrative Route | API5:2023 Broken Function Level Authorization | Critical |
| **API-AUTH-003** | Insecure HTTP Basic Authentication | API2:2023 Broken Authentication | Medium |
| **API-AUTH-005** | Missing Global Security Schemes in Contract | API2:2023 Broken Authentication | Medium |
| **API-BOLA-001** | Direct Object Identifier in Route (BOLA / IDOR) | API1:2023 Broken Object Level Authorization | High |
| **API-BOLA-002** | Predictable Sequential Integer Identifier | API1:2023 Broken Object Level Authorization | Low |
| **API-BFLA-001** | Privileged Admin Path Missing Granular Scopes | API5:2023 Broken Function Level Authorization | High |
| **API-BFLA-003** | High-Risk Privilege Escalation Endpoint Pattern | API5:2023 Broken Function Level Authorization | High |
| **API-DATA-001** | Secret / Password Hash in Response Schema | API3:2023 Broken Object Property Authorization | Critical |
| **API-DATA-002** | High-Sensitivity PII / Financial Identifier | API3:2023 Broken Object Property Authorization | High |
| **API-DATA-003** | Sensitive Credentials in Query Parameters | API3:2023 Broken Object Property Authorization | High |
| **API-EXCESS-001**| Internal Metadata / Proprietary Business Fields | API3:2023 Broken Object Property Authorization | Medium |
| **API-HTTP-001** | State Mutation Action Executed via HTTP GET | API8:2023 Security Misconfiguration | High |
| **API-RATE-001** | Sensitive Flow Missing Documented Rate Limits | API4:2023 Unrestricted Resource Consumption | High / Medium |
| **API-CONF-001** | Insecure Plaintext HTTP Server URL Scheme | API8:2023 Security Misconfiguration | High |
| **API-CONF-003** | Stack Trace / Debug Leakage in 500 Error Schema | API8:2023 Security Misconfiguration | Low |
| **API-VAL-001**  | Unconstrained String Parameters Without Bounds | API8:2023 Security Misconfiguration | Low |
| **API-VAL-003**  | Unbounded Array Payload in Request Body | API4:2023 Unrestricted Resource Consumption | Low |
| **API-SSRF-001** | Potential Server-Side Request Forgery via URL | API7:2023 Server Side Request Forgery | High |
| **API-UPLOAD-001**| File Upload Missing Documented MIME / Size Limit | API8:2023 Security Misconfiguration | Medium |
| **API-BIZ-001**  | Sensitive Financial Transaction Flow | API6:2023 Sensitive Business Flows | High |
| **API-BIZ-002**  | Coupon / Incentive Concurrency Race Risk | API6:2023 Sensitive Business Flows | Medium |
| **API-VER-002**  | Multiple Legacy Major API Versions Coexisting | API9:2023 Improper Inventory Management | Medium |
| **API-VER-003**  | Internal / Test / Debug Path in Spec | API9:2023 Improper Inventory Management | High |

---

## 🚀 Quick Start Guide

### Prerequisites
* **Node.js**: v18+ (tested on Node v24)
* **Python**: v3.10+ (tested on Python 3.14)
* **MongoDB**: Atlas connection or local MongoDB (or uses resilient in-memory development store automatically)

### 1. Security Engine Setup (Python FastAPI)
```bash
cd security-engine
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000 --reload
```

### 2. Backend Server Setup (Node.js Express)
```bash
cd server
npm install
npm start
# Server listens on http://localhost:5000
```

### 3. Frontend Client Setup (React Vite)
```bash
cd client
npm install
npm run dev
# Frontend runs on http://localhost:5173
```

---

## 🧪 Running Automated Tests

### Python Security Rules & Parser Test Suite:
```bash
cd security-engine
python -m pytest tests
```

### Backend Integration Test Suite:
```bash
cd server
npm test
```

---

## 🔐 Environment Variables

Create `.env` in `server/` with the following:
```env
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173
SECURITY_ENGINE_URL=http://127.0.0.1:8000
MONGODB_URI=mongodb://127.0.0.1:27017/api-sentinel
JWT_SECRET=sentinel_jwt_secret_production_key_change_in_prod_998811
JWT_EXPIRES_IN=7d
MAX_UPLOAD_SIZE_MB=15
```

---

## 📄 License
MIT License • Created for Enterprise API Security Posture Analysis.
