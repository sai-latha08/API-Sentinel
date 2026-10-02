import uuid
from typing import List, Dict, Any
from app.schemas.models import EndpointDefinition, SecurityFinding

class FileUploadAnalyzer:
    @staticmethod
    def analyze(meta: Dict[str, Any], endpoints: List[EndpointDefinition]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        for ep in endpoints:
            is_upload = False
            upload_reasons = []

            # Check content types
            if ep.request_body:
                for ct in ep.request_body.content_types:
                    if "multipart/form-data" in ct or "application/octet-stream" in ct:
                        is_upload = True
                        upload_reasons.append(f"Content-Type: {ct}")

            # Check path
            path_lower = ep.path.lower()
            if any(w in path_lower for w in ["upload", "avatar", "attachment", "document/upload", "import-file", "media/upload"]):
                is_upload = True
                upload_reasons.append(f"Upload keyword in path: '{ep.path}'")

            # Check parameters with type: binary or file
            for p in ep.parameters:
                if p.param_type in ["binary", "file"] or p.format == "binary":
                    is_upload = True
                    upload_reasons.append(f"Binary parameter '{p.name}'")

            if is_upload:
                # Inspect schema for type/size restrictions
                has_mime_restriction = False
                has_size_limit = False
                if ep.request_body and ep.request_body.schema_details:
                    desc = str(ep.request_body.schema_details).lower()
                    if any(w in desc for w in ["png", "jpeg", "pdf", "mime", "content-type"]):
                        has_mime_restriction = True
                    if any(w in desc for w in ["maxlength", "maxsize", "bytes", "limit", "mb"]):
                        has_size_limit = True

                if not has_mime_restriction or not has_size_limit:
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        rule_id="API-UPLOAD-001",
                        title="File Upload Security Restrictions Not Documented",
                        category="File Upload Security",
                        severity="MEDIUM",
                        confidence=0.85,
                        endpoint=ep.path,
                        method=ep.method,
                        description=f"Endpoint '{ep.method} {ep.path}' handles file uploads ({', '.join(upload_reasons)}), but explicit file extension allowlists, MIME type constraints, and maximum upload byte limits are not documented in the API specification.",
                        evidence=f"File upload handler without documented MIME validation or max file size.",
                        impact="Unrestricted file upload capabilities can lead to Remote Code Execution (RCE) via web shell uploads (.php, .jsp, .exe), stored cross-site scripting (SVG XSS), or storage disk exhaustion.",
                        recommendation="Enforce a strict whitelist of allowed file extensions and MIME magic bytes. Restrict upload size (e.g. max 5MB) and store uploaded assets in an isolated cloud bucket (e.g. AWS S3) with randomized filenames and Content-Disposition: attachment headers.",
                        fix_code_example="""// Multer Upload Security Guard
import multer from 'multer';

const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'application/pdf'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPG, PNG, and PDF are permitted.'));
    }
  }
});""",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/434.html"
                        ],
                        cwe_id="CWE-434",
                        owasp_category="API8:2023 Security Misconfiguration"
                    ))

        return findings
