import json
import yaml
import re
from typing import Dict, Any, List, Tuple
from app.schemas.models import (
    EndpointDefinition, ParameterSchema, RequestBodySchema, ResponseSchema
)
from app.parsers.openapi_parser import resolve_ref, flatten_schema

class SwaggerParser:
    def __init__(self, raw_content: str):
        self.raw_content = raw_content
        self.spec: Dict[str, Any] = self._load_content(raw_content)

    def _load_content(self, content: str) -> Dict[str, Any]:
        content_stripped = content.strip()
        if content_stripped.startswith('{') or content_stripped.startswith('['):
            try:
                return json.loads(content)
            except Exception:
                pass
        try:
            parsed = yaml.safe_load(content)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
        try:
            return json.loads(content)
        except Exception as e:
            raise ValueError(f"Failed to parse Swagger document: {str(e)}")

    def parse(self) -> Tuple[Dict[str, Any], List[EndpointDefinition]]:
        if not isinstance(self.spec, dict):
            raise ValueError("Invalid Swagger document: root must be an object.")

        info = self.spec.get("info", {})
        title = info.get("title", "Swagger 2.0 API")
        version = str(info.get("version", "1.0.0"))
        description = info.get("description", "")

        host = self.spec.get("host", "")
        base_path = self.spec.get("basePath", "")
        schemes = self.spec.get("schemes", ["https"])
        
        servers = []
        if host:
            for sc in schemes:
                servers.append(f"{sc}://{host}{base_path}")
        elif base_path:
            servers.append(base_path)

        global_security = self.spec.get("security", [])
        security_schemes = self.spec.get("securityDefinitions", {})

        meta = {
            "title": title,
            "version": version,
            "description": description,
            "servers": servers,
            "format": "swagger_2",
            "global_security": global_security,
            "security_schemes": security_schemes,
            "raw_spec": self.spec
        }

        endpoints: List[EndpointDefinition] = []
        paths = self.spec.get("paths", {})
        if not isinstance(paths, dict):
            return meta, endpoints

        valid_methods = {"get", "post", "put", "delete", "patch", "options", "head"}

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_level_params = path_item.get("parameters", [])

            for method_str, op in path_item.items():
                method_lower = method_str.lower()
                if method_lower not in valid_methods:
                    continue
                if not isinstance(op, dict):
                    continue

                op_id = op.get("operationId", f"{method_lower}_{path_str.replace('/', '_')}")
                summary = op.get("summary")
                desc = op.get("description")
                tags = op.get("tags", [])
                deprecated = bool(op.get("deprecated", False))

                op_security = op.get("security", None)
                effective_security = global_security if op_security is None else op_security

                is_auth = False
                if effective_security:
                    for sec_item in effective_security:
                        if sec_item and len(sec_item) > 0:
                            is_auth = True
                            break

                all_raw_params = list(path_level_params) + op.get("parameters", [])
                parameters: List[ParameterSchema] = []
                req_body_obj = None

                for p in all_raw_params:
                    if not isinstance(p, dict):
                        continue
                    if "$ref" in p:
                        p = resolve_ref(p["$ref"], self.spec)

                    p_name = p.get("name", "unnamed")
                    p_in = p.get("in", "query")
                    p_req = bool(p.get("required", False or p_in == "path"))
                    p_desc = p.get("description")
                    p_type = p.get("type", "string")
                    p_format = p.get("format")

                    if p_in == "body":
                        b_schema = p.get("schema", {})
                        if "$ref" in b_schema:
                            b_schema = resolve_ref(b_schema["$ref"], self.spec)
                        req_body_obj = RequestBodySchema(
                            required=p_req,
                            content_types=op.get("consumes", ["application/json"]),
                            schema_details=flatten_schema(b_schema, self.spec)
                        )
                    else:
                        parameters.append(ParameterSchema(
                            name=p_name,
                            in_location=p_in,
                            required=p_req,
                            param_type=p_type,
                            format=p_format,
                            description=p_desc,
                            schema_details=p
                        ))

                responses_list: List[ResponseSchema] = []
                raw_responses = op.get("responses", {})
                if isinstance(raw_responses, dict):
                    for status_code, resp_data in raw_responses.items():
                        if "$ref" in resp_data:
                            resp_data = resolve_ref(resp_data["$ref"], self.spec)
                        if not isinstance(resp_data, dict):
                            continue
                        r_desc = resp_data.get("description", "")
                        r_schema = resp_data.get("schema", {})
                        if "$ref" in r_schema:
                            r_schema = resolve_ref(r_schema["$ref"], self.spec)
                        r_headers = list(resp_data.get("headers", {}).keys()) if isinstance(resp_data.get("headers"), dict) else []
                        responses_list.append(ResponseSchema(
                            status_code=str(status_code),
                            description=r_desc,
                            content_types=op.get("produces", ["application/json"]),
                            headers=r_headers,
                            schema_details=flatten_schema(r_schema, self.spec)
                        ))

                endpoint_id = f"{method_lower.upper()}_{re.sub(r'[^a-zA-Z0-9]', '_', path_str)}"
                sensitivity_score, sensitivity_reasons = self._calculate_sensitivity(path_str, method_lower, is_auth)

                endpoints.append(EndpointDefinition(
                    id=endpoint_id,
                    path=path_str,
                    method=method_lower.upper(),
                    summary=summary,
                    description=desc,
                    operation_id=op_id,
                    tags=tags,
                    security_requirements=effective_security,
                    is_authenticated=is_auth,
                    parameters=parameters,
                    request_body=req_body_obj,
                    responses=responses_list,
                    is_deprecated=deprecated,
                    sensitivity_score=sensitivity_score,
                    sensitivity_reasons=sensitivity_reasons
                ))

        return meta, endpoints

    def _calculate_sensitivity(self, path: str, method: str, is_auth: bool) -> Tuple[float, List[str]]:
        score = 0.2
        reasons = []
        path_lower = path.lower()
        if any(w in path_lower for w in ["admin", "administrator", "manage", "root", "system"]):
            score += 0.4
            reasons.append("Administrative keywords detected")
        if any(w in path_lower for w in ["auth", "login", "register", "password", "token", "otp"]):
            score += 0.35
            reasons.append("Authentication/Credential endpoints")
        if any(w in path_lower for w in ["payment", "checkout", "billing", "refund", "transfer"]):
            score += 0.35
            reasons.append("Financial flow")
        if any(w in path_lower for w in ["user", "account", "profile", "order"]):
            score += 0.2
            reasons.append("Core user entity")
        if method in ["delete", "put", "patch"]:
            score += 0.15
            reasons.append(f"Destructive method {method.upper()}")
        if not is_auth:
            score += 0.1
            reasons.append("Unauthenticated")
        return min(1.0, round(score, 2)), reasons
