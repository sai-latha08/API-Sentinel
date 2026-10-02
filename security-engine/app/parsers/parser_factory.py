import json
import yaml
from typing import Dict, Any, List, Tuple
from app.schemas.models import EndpointDefinition
from app.parsers.openapi_parser import OpenAPIParser
from app.parsers.swagger_parser import SwaggerParser
from app.parsers.postman_parser import PostmanParser

class SpecParserFactory:
    @staticmethod
    def parse_spec(raw_content: str) -> Tuple[Dict[str, Any], List[EndpointDefinition]]:
        if not raw_content or not raw_content.strip():
            raise ValueError("Specification content is empty.")

        # Attempt to inspect JSON / YAML structure
        doc: Dict[str, Any] = {}
        content_stripped = raw_content.strip()
        
        # Try JSON
        if content_stripped.startswith('{') or content_stripped.startswith('['):
            try:
                doc = json.loads(raw_content)
            except Exception:
                pass

        # Try YAML if JSON failed
        if not doc:
            try:
                doc = yaml.safe_load(raw_content)
            except Exception:
                pass

        if not isinstance(doc, dict):
            # Final fallback attempt
            try:
                doc = json.loads(raw_content)
            except Exception as e:
                raise ValueError(f"Unable to parse document as valid JSON or YAML: {str(e)}")

        # Format detection
        if "openapi" in doc and str(doc["openapi"]).startswith("3"):
            parser = OpenAPIParser(raw_content)
            return parser.parse()
        elif "swagger" in doc and str(doc["swagger"]).startswith("2"):
            parser = SwaggerParser(raw_content)
            return parser.parse()
        elif "info" in doc and ("_postman_id" in doc.get("info", {}) or "schema" in doc.get("info", {}) and "postman" in str(doc.get("info", {}).get("schema"))):
            parser = PostmanParser(raw_content)
            return parser.parse()
        elif "item" in doc and isinstance(doc["item"], list):
            # Postman collection structure
            parser = PostmanParser(raw_content)
            return parser.parse()
        elif "paths" in doc:
            # Likely OpenAPI 3.x default
            parser = OpenAPIParser(raw_content)
            return parser.parse()
        else:
            raise ValueError(
                "Unrecognized API specification format. Supported formats: OpenAPI 3.x (JSON/YAML), Swagger 2.0 (JSON/YAML), Postman Collection v2.0/v2.1 (JSON)."
            )
