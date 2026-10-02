from typing import List, Dict, Any
from app.schemas.models import (
    EndpointDefinition, SecurityFinding, AttackSurfaceGraph, GraphNode, GraphEdge
)

class AttackSurfaceBuilder:
    @staticmethod
    def build_graph(
        api_title: str,
        meta: Dict[str, Any],
        endpoints: List[EndpointDefinition],
        findings: List[SecurityFinding]
    ) -> AttackSurfaceGraph:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []

        # 1. API Root Node
        root_id = "api_root"
        nodes.append(GraphNode(
            id=root_id,
            type="apiRoot",
            position={"x": 500.0, "y": 50.0},
            data={
                "label": api_title or "API Specification",
                "version": meta.get("version", "1.0.0"),
                "totalEndpoints": len(endpoints),
                "totalFindings": len(findings)
            }
        ))

        # 2. Auth Scheme Nodes
        security_schemes = meta.get("security_schemes", {})
        auth_nodes = []
        if security_schemes:
            x_offset = 250.0
            idx = 0
            for s_name, s_def in security_schemes.items():
                s_id = f"auth_{s_name}"
                auth_type = s_def.get("type", "custom") if isinstance(s_def, dict) else "custom"
                nodes.append(GraphNode(
                    id=s_id,
                    type="authScheme",
                    position={"x": x_offset + (idx * 280.0), "y": 200.0},
                    data={
                        "label": s_name,
                        "type": auth_type,
                        "details": s_def
                    }
                ))
                edges.append(GraphEdge(
                    id=f"e_root_{s_id}",
                    source=root_id,
                    target=s_id,
                    label="secures",
                    animated=True
                ))
                auth_nodes.append(s_id)
                idx += 1
        else:
            # Public / Default Auth node
            s_id = "auth_public"
            nodes.append(GraphNode(
                id=s_id,
                type="authScheme",
                position={"x": 500.0, "y": 200.0},
                data={
                    "label": "Public / No Global Auth",
                    "type": "none",
                    "details": "No global security scheme defined"
                }
            ))
            edges.append(GraphEdge(
                id=f"e_root_{s_id}",
                source=root_id,
                target=s_id,
                label="default"
            ))
            auth_nodes.append(s_id)

        # 3. Endpoint Nodes (Grouped & Placed logically)
        # To avoid visual clutter, pick up to 12 representative / high-priority endpoints for graph
        sorted_eps = sorted(endpoints, key=lambda e: e.sensitivity_score, reverse=True)
        display_eps = sorted_eps[:10] if len(sorted_eps) > 10 else sorted_eps

        col_count = min(len(display_eps), 4) or 1
        ep_spacing_x = 260.0
        start_x = 500.0 - ((col_count - 1) * ep_spacing_x / 2.0)

        for i, ep in enumerate(display_eps):
            col = i % col_count
            row = i // col_count
            ep_x = start_x + (col * ep_spacing_x)
            ep_y = 380.0 + (row * 140.0)

            # Find findings specific to this endpoint
            ep_findings = [f for f in findings if f.endpoint == ep.path or f.endpoint == f"{ep.method} {ep.path}"]
            highest_sev = "INFO"
            for f in ep_findings:
                if f.severity == "CRITICAL":
                    highest_sev = "CRITICAL"
                    break
                elif f.severity == "HIGH" and highest_sev != "CRITICAL":
                    highest_sev = "HIGH"
                elif f.severity == "MEDIUM" and highest_sev not in ["CRITICAL", "HIGH"]:
                    highest_sev = "MEDIUM"

            nodes.append(GraphNode(
                id=ep.id,
                type="endpoint",
                position={"x": ep_x, "y": ep_y},
                data={
                    "path": ep.path,
                    "method": ep.method,
                    "isAuth": ep.is_authenticated,
                    "sensitivity": ep.sensitivity_score,
                    "riskLevel": highest_sev,
                    "findingsCount": len(ep_findings)
                }
            ))

            # Connect to Auth node
            parent_auth = auth_nodes[0] if auth_nodes else root_id
            edges.append(GraphEdge(
                id=f"e_auth_{ep.id}",
                source=parent_auth,
                target=ep.id
            ))

        # 4. Sensitive Asset & Risk Nodes connected to highest risk endpoints
        high_risk_findings = [f for f in findings if f.severity in ["CRITICAL", "HIGH"]][:6]
        finding_y = 660.0
        for idx, f in enumerate(high_risk_findings):
            f_node_id = f"finding_{f.rule_id}_{idx}"
            f_x = 180.0 + (idx * 210.0)
            
            nodes.append(GraphNode(
                id=f_node_id,
                type="riskFinding",
                position={"x": f_x, "y": finding_y + (40.0 if idx % 2 == 1 else 0.0)},
                data={
                    "ruleId": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category
                }
            ))

            # Connect finding to matching endpoint node if present in display_eps
            matched_ep = next((e for e in display_eps if e.path == f.endpoint or f.endpoint.endswith(e.path)), None)
            if matched_ep:
                edges.append(GraphEdge(
                    id=f"e_ep_{f_node_id}",
                    source=matched_ep.id,
                    target=f_node_id,
                    label=f.severity,
                    animated=True,
                    style={"stroke": "#DC2626" if f.severity == "CRITICAL" else "#EA580C"}
                ))
            elif display_eps:
                # Connect to first sensitive endpoint
                edges.append(GraphEdge(
                    id=f"e_ep_{f_node_id}",
                    source=display_eps[0].id,
                    target=f_node_id,
                    label=f.severity,
                    style={"stroke": "#EA580C"}
                ))

        return AttackSurfaceGraph(nodes=nodes, edges=edges)
