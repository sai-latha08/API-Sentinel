import json
import re
from typing import Dict, Any, List, Tuple, Optional
from app.schemas.models import (
    EndpointDefinition, ParameterSchema, RequestBodySchema, ResponseSchema
)

class PostmanParser:
    def __init__(self, raw_content: str):
        self.raw_content = raw_content
        self.spec: Dict[str, Any] = self._load_content(raw_content)

    def _load_content(self, content: str) -> Dict[str, Any]:
        try:
            return json.loads(content)
        except Exception as e:
            raise ValueError(f"Failed to parse Postman collection JSON: {str(e)}")

    def parse(self) -> Tuple[Dict[str, Any], List[EndpointDefinition]]:
        if not isinstance(self.spec, dict):
            raise ValueError("Invalid Postman collection: root must be an object.")

        info = self.spec.get("info", {})
        title = info.get("name", "Postman Collection")
        version = info.get("version", "1.0.0")
        if isinstance(version, dict):
            version = f"{version.get('major', 1)}.{version.get('minor', 0)}.{version.get('patch', 0)}"
        description = info.get("description", "")

        collection_auth = self.spec.get("auth", None)
        global_security = []
        security_schemes = {}
        if collection_auth and isinstance(collection_auth, dict):
            auth_type = collection_auth.get("type", "unknown")
            global_security.append({auth_type: []})
            security_schemes[auth_type] = {"type": auth_type}

        meta = {
            "title": title,
            "version": str(version),
            "description": description,
            "servers": [],
            "format": "postman",
            "global_security": global_security,
            "security_schemes": security_schemes,
            "raw_spec": self.spec
        }

        raw_items = self.spec.get("item", [])
        endpoints: List[EndpointDefinition] = []

        def extract_items(items_list: List[Dict[str, Any]], folder_tags: List[str]):
            for item in items_list:
                if not isinstance(item, dict):
                    continue
                if "item" in item and isinstance(item["item"], list):
                    # It's a folder
                    folder_name = item.get("name", "Folder")
                    extract_items(item["item"], folder_tags + [folder_name])
                elif "request" in item:
                    # It's an API request
                    endpoint_def = self._parse_request_item(item, folder_tags, global_security)
                    if endpoint_def:
                        endpoints.append(endpoint_def)

        extract_items(raw_items, [])
        return meta, endpoints

    def _parse_request_item(self, item: Dict[str, Any], tags: List[str], global_security: List[Any]) -> Optional[EndpointDefinition]:
        req = item.get("request")
        if not req:
            return None

        if isinstance(req, str):
            # Simple URL string
            method = "GET"
            raw_url = req
            headers = []
            auth_data = None
            body_data = None
        else:
            method = req.get("method", "GET").upper()
            raw_url = req.get("url", "")
            headers = req.get("header", [])
            auth_data = req.get("auth")
            body_data = req.get("body")

        # Normalize URL / Path
        path = "/"
        params: List[ParameterSchema] = []
        if isinstance(raw_url, dict):
            raw_path_parts = raw_url.get("path", [])
            if isinstance(raw_path_parts, list):
                path = "/" + "/".join(str(p) for p in raw_path_parts)
            elif isinstance(raw_path_parts, str):
                path = raw_path_parts if raw_path_parts.startswith("/") else "/" + raw_path_parts

            # Extract Query parameters
            for q in raw_url.get("query", []):
                if isinstance(q, dict):
                    q_key = q.get("key", "")
                    if q_key:
                        params.append(ParameterSchema(
                            name=q_key,
                            in_location="query",
                            required=False,
                            param_type="string",
                            description=q.get("description")
                        ))

            # Extract Path variables (:id or {{id}})
            for v in raw_url.get("variable", []):
                if isinstance(v, dict):
                    v_key = v.get("key", "")
                    if v_key:
                        params.append(ParameterSchema(
                            name=v_key,
                            in_location="path",
                            required=True,
                            param_type="string",
                            description=v.get("description")
                        ))
        elif isinstance(raw_url, str):
            # Parse path from string
            clean_url = re.sub(r'^https?://[^/]+', '', raw_url)
            path = clean_url.split('?')[0]
            if not path.startswith('/'):
                path = '/' + path

        # Normalize path params pattern (:userId -> {userId})
        normalized_path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', path)

        # Authentication resolution
        is_auth = False
        effective_sec = []
        if auth_data and isinstance(auth_data, dict) and auth_data.get("type") != "noauth":
            is_auth = True
            effective_sec = [{auth_data.get("type", "custom"): []}]
        elif global_security and auth_data is None:
            is_auth = True
            effective_sec = global_security

        # Header check for Authorization
        for h in headers:
            if isinstance(h, dict):
                h_key = h.get("key", "").lower()
                if h_key in ["authorization", "x-api-key", "apikey", "bearer"]:
                    is_auth = True
                    effective_sec = [{"header_auth": []}]
                params.append(ParameterSchema(
                    name=h.get("key", ""),
                    in_location="header",
                    required=False,
                    param_type="string",
                    description=h.get("description")
                ))

        # Body parsing
        req_body = None
        if body_data and isinstance(body_data, dict):
            mode = body_data.get("mode", "raw")
            raw_text = body_data.get("raw", "")
            content_type = "application/json"
            schema_details = {}
            if mode == "raw" and raw_text:
                try:
                    parsed_json = json.loads(raw_text)
                    if isinstance(parsed_json, dict):
                        schema_details = {
                            "type": "object",
                            "properties": {k: {"type": type(v).__name__} for k, v in parsed_json.items()}
                        }
                except Exception:
                    schema_details = {"type": "string"}
            elif mode == "formdata":
                content_type = "multipart/form-data"
                schema_details = {"type": "object", "properties": {}}
            elif mode == "urlencoded":
                content_type = "application/x-www-form-urlencoded"
                schema_details = {"type": "object", "properties": {}}

            req_body = RequestBodySchema(
                required=True,
                content_types=[content_type],
                schema_details=schema_details
            )

        # Responses from saved sample responses
        responses_list: List[ResponseSchema] = []
        for resp in item.get("response", []):
            if isinstance(resp, dict):
                code = str(resp.get("code", 200))
                resp_body = resp.get("body", "")
                resp_schema = {}
                if resp_body:
                    try:
                        resp_json = json.loads(resp_body)
                        if isinstance(resp_json, dict):
                            resp_schema = {
                                "type": "object",
                                "properties": {k: {"type": type(v).__name__} for k, v in resp_json.items()}
                            }
                    except Exception:
                        resp_schema = {"type": "string"}
                responses_list.append(ResponseSchema(
                    status_code=code,
                    description=resp.get("name", ""),
                    content_types=["application/json"],
                    schema_details=resp_schema
                ))

        endpoint_id = f"{method}_{re.sub(r'[^a-zA-Z0-9]', '_', normalized_path)}"
        sensitivity_score, sensitivity_reasons = self._calculate_sensitivity(normalized_path, method.lower(), is_auth)

        return EndpointDefinition(
            id=endpoint_id,
            path=normalized_path,
            method=method,
            summary=item.get("name"),
            description=req.get("description") if isinstance(req, dict) else None,
            operation_id=item.get("name", "").replace(" ", "_"),
            tags=tags,
            security_requirements=effective_sec,
            is_authenticated=is_auth,
            parameters=params,
            request_body=req_body,
            responses=responses_list,
            is_deprecated=False,
            sensitivity_score=sensitivity_score,
            sensitivity_reasons=sensitivity_reasons
        )

    def _calculate_sensitivity(self, path: str, method: str, is_auth: bool) -> Tuple[float, List[str]]:
        score = 0.2
        reasons = []
        path_lower = path.lower()
        if any(w in path_lower for w in ["admin", "manage", "root", "internal"]):
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
