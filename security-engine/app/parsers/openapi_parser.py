import json
import yaml
import re
from typing import Dict, Any, List, Tuple, Optional
from app.schemas.models import (
    EndpointDefinition, ParameterSchema, RequestBodySchema, ResponseSchema
)

def resolve_ref(ref_str: str, root_doc: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    """Resolve JSON pointer references like #/components/schemas/User"""
    if depth > 5 or not isinstance(ref_str, str) or not ref_str.startswith('#/'):
        return {}
    parts = ref_str.lstrip('#/').split('/')
    curr = root_doc
    for part in parts:
        part = part.replace('~1', '/').replace('~0', '~')
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return {}
    if isinstance(curr, dict) and '$ref' in curr:
        return resolve_ref(curr['$ref'], root_doc, depth + 1)
    return curr if isinstance(curr, dict) else {}

def flatten_schema(schema: Dict[str, Any], root_doc: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    """Recursively expand schema properties and resolve $refs"""
    if depth > 4 or not isinstance(schema, dict):
        return schema if isinstance(schema, dict) else {}
    
    resolved = dict(schema)
    if '$ref' in resolved:
        ref_data = resolve_ref(resolved['$ref'], root_doc)
        resolved.pop('$ref', None)
        resolved.update(ref_data)
        
    if 'allOf' in resolved and isinstance(resolved['allOf'], list):
        merged_props = {}
        for sub in resolved['allOf']:
            sub_flat = flatten_schema(sub, root_doc, depth + 1)
            if 'properties' in sub_flat:
                merged_props.update(sub_flat['properties'])
        if 'properties' not in resolved:
            resolved['properties'] = {}
        resolved['properties'].update(merged_props)

    if 'properties' in resolved and isinstance(resolved['properties'], dict):
        flat_props = {}
        for prop_name, prop_val in resolved['properties'].items():
            if isinstance(prop_val, dict):
                flat_props[prop_name] = flatten_schema(prop_val, root_doc, depth + 1)
            else:
                flat_props[prop_name] = prop_val
        resolved['properties'] = flat_props
        
    if 'items' in resolved and isinstance(resolved['items'], dict):
        resolved['items'] = flatten_schema(resolved['items'], root_doc, depth + 1)
        
    return resolved

class OpenAPIParser:
    def __init__(self, raw_content: str):
        self.raw_content = raw_content
        self.spec: Dict[str, Any] = self._load_content(raw_content)
        
    def _load_content(self, content: str) -> Dict[str, Any]:
        content_stripped = content.strip()
        if content_stripped.startswith('{') or content_stripped.startswith('['):
            try:
                return json.loads(content)
            except Exception as e:
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
            raise ValueError(f"Failed to parse OpenAPI document as JSON or YAML: {str(e)}")

    def parse(self) -> Tuple[Dict[str, Any], List[EndpointDefinition]]:
        if not isinstance(self.spec, dict):
            raise ValueError("Invalid OpenAPI document: root must be an object.")
            
        info = self.spec.get("info", {})
        title = info.get("title", "Untitled API")
        version = str(info.get("version", "1.0.0"))
        description = info.get("description", "")
        
        servers = []
        for s in self.spec.get("servers", []):
            if isinstance(s, dict) and "url" in s:
                servers.append(s["url"])
            elif isinstance(s, str):
                servers.append(s)
                
        global_security = self.spec.get("security", [])
        security_schemes = self.spec.get("components", {}).get("securitySchemes", {})
        
        meta = {
            "title": title,
            "version": version,
            "description": description,
            "servers": servers,
            "format": "openapi_3",
            "global_security": global_security,
            "security_schemes": security_schemes,
            "raw_spec": self.spec
        }
        
        endpoints: List[EndpointDefinition] = []
        paths = self.spec.get("paths", {})
        if not isinstance(paths, dict):
            return meta, endpoints

        valid_methods = {"get", "post", "put", "delete", "patch", "options", "head", "trace"}
        
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
                
                # Security resolution
                op_security = op.get("security", None)
                if op_security is None:
                    effective_security = global_security
                else:
                    effective_security = op_security
                
                is_auth = False
                if effective_security:
                    # If empty list [] or [{}] it's explicit public
                    for sec_item in effective_security:
                        if sec_item and len(sec_item) > 0:
                            is_auth = True
                            break
                            
                # Parameter parsing
                all_raw_params = list(path_level_params) + op.get("parameters", [])
                parameters: List[ParameterSchema] = []
                for p in all_raw_params:
                    if not isinstance(p, dict):
                        continue
                    if "$ref" in p:
                        p = resolve_ref(p["$ref"], self.spec)
                    p_name = p.get("name", "unnamed")
                    p_in = p.get("in", "query")
                    p_req = bool(p.get("required", False or p_in == "path"))
                    p_desc = p.get("description")
                    p_schema = p.get("schema", {})
                    if "$ref" in p_schema:
                        p_schema = resolve_ref(p_schema["$ref"], self.spec)
                    p_type = p_schema.get("type", "string")
                    p_format = p_schema.get("format")
                    
                    parameters.append(ParameterSchema(
                        name=p_name,
                        in_location=p_in,
                        required=p_req,
                        param_type=p_type,
                        format=p_format,
                        description=p_desc,
                        schema_details=flatten_schema(p_schema, self.spec)
                    ))
                    
                # Request Body
                req_body_obj = None
                raw_req_body = op.get("requestBody")
                if raw_req_body:
                    if "$ref" in raw_req_body:
                        raw_req_body = resolve_ref(raw_req_body["$ref"], self.spec)
                    if isinstance(raw_req_body, dict):
                        req_required = bool(raw_req_body.get("required", False))
                        content_dict = raw_req_body.get("content", {})
                        content_types = list(content_dict.keys())
                        first_schema = {}
                        if content_types:
                            first_content = content_dict.get(content_types[0], {})
                            first_schema = flatten_schema(first_content.get("schema", {}), self.spec)
                        req_body_obj = RequestBodySchema(
                            required=req_required,
                            content_types=content_types,
                            schema_details=first_schema
                        )

                # Responses
                responses_list: List[ResponseSchema] = []
                raw_responses = op.get("responses", {})
                if isinstance(raw_responses, dict):
                    for status_code, resp_data in raw_responses.items():
                        if "$ref" in resp_data:
                            resp_data = resolve_ref(resp_data["$ref"], self.spec)
                        if not isinstance(resp_data, dict):
                            continue
                        r_desc = resp_data.get("description", "")
                        r_content = resp_data.get("content", {})
                        r_ctypes = list(r_content.keys()) if isinstance(r_content, dict) else []
                        r_headers = list(resp_data.get("headers", {}).keys()) if isinstance(resp_data.get("headers"), dict) else []
                        r_schema = {}
                        if r_ctypes:
                            first_ct = r_content.get(r_ctypes[0], {})
                            r_schema = flatten_schema(first_ct.get("schema", {}), self.spec)
                        responses_list.append(ResponseSchema(
                            status_code=str(status_code),
                            description=r_desc,
                            content_types=r_ctypes,
                            headers=r_headers,
                            schema_details=r_schema
                        ))
                
                endpoint_id = f"{method_lower.upper()}_{re.sub(r'[^a-zA-Z0-9]', '_', path_str)}"
                
                # Sensitivity calculation
                sensitivity_score, sensitivity_reasons = self._calculate_sensitivity(path_str, method_lower, is_auth, tags)
                
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

    def _calculate_sensitivity(self, path: str, method: str, is_auth: bool, tags: List[str]) -> Tuple[float, List[str]]:
        score = 0.2
        reasons = []
        path_lower = path.lower()
        
        # High sensitivity words
        admin_words = ["admin", "administrator", "manage", "root", "system", "internal", "config", "setting", "role", "permission"]
        for w in admin_words:
            if w in path_lower:
                score += 0.4
                reasons.append(f"Administrative keyword detected: '{w}'")
                break
                
        auth_words = ["auth", "login", "register", "signup", "password", "token", "otp", "oauth", "session", "credential"]
        for w in auth_words:
            if w in path_lower:
                score += 0.35
                reasons.append(f"Authentication/Credential flow keyword: '{w}'")
                break
                
        financial_words = ["payment", "checkout", "billing", "wallet", "invoice", "refund", "transfer", "withdraw", "card", "bank", "crypto"]
        for w in financial_words:
            if w in path_lower:
                score += 0.35
                reasons.append(f"Financial transaction keyword: '{w}'")
                break
                
        data_words = ["user", "account", "profile", "customer", "order", "document", "file", "upload", "download"]
        for w in data_words:
            if w in path_lower:
                score += 0.2
                reasons.append(f"Core user/data asset keyword: '{w}'")
                break

        if method in ["delete", "put", "patch"]:
            score += 0.15
            reasons.append(f"Destructive/Mutating HTTP method '{method.upper()}'")
            
        if not is_auth:
            score += 0.1
            reasons.append("Unauthenticated / Public accessibility")
            
        return min(1.0, round(score, 2)), reasons
