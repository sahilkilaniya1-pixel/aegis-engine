import json
import re
from typing import Dict, Any, List

class GraphQLParser:
    """
    GraphQL queries, mutations, aur introspection data ko parse karke 
    potential security risks (jaise batching attacks, introspection leaks, alias overloading) detect karta hai.
    """
    @staticmethod
    def parse_query(payload: Any) -> Dict[str, Any]:
        vulnerabilities = []
        
        # 1. Check for Batching Attacks (Array of queries)
        is_batched = isinstance(payload, list)
        if is_batched:
            vulnerabilities.append({
                "type": "GraphQL Batching Abuse",
                "severity": "Medium",
                "description": "Multiple queries submitted in a single batched request, potential DoS risk."
            })
            payload = payload[0] if payload else {}

        query = payload.get("query", "") if isinstance(payload, dict) else ""
        variables = payload.get("variables", {}) if isinstance(payload, dict) else {}
        operation_name = payload.get("operationName") if isinstance(payload, dict) else None
        
        # Query se fields extract karna
        fields = re.findall(r'(\w+)\s*(?:\(|{)', query)
        
        # Check karna ki kya introspection enabled hai (information disclosure risk)
        is_introspection = "__schema" in query or "__type" in query
        if is_introspection:
            vulnerabilities.append({
                "type": "GraphQL Introspection Enabled",
                "severity": "Low",
                "description": "Introspection is active, allowing attackers to map the entire schema."
            })

        # Query Depth / Nesting Analysis
        max_depth = query.count('{')
        if max_depth > 5:
            vulnerabilities.append({
                "type": "Deeply Nested GraphQL Query",
                "severity": "Medium",
                "description": f"Query depth is high ({max_depth} levels), risking server resource exhaustion."
            })

        # Alias Overloading Detection
        alias_count = len(re.findall(r'\w+:\s*\w+\(', query))
        if alias_count > 10:
            vulnerabilities.append({
                "type": "GraphQL Alias Overloading",
                "severity": "High",
                "description": f"Excessive aliases detected ({alias_count}), potential batching/DoS vector."
            })

        return {
            "operation_name": operation_name,
            "variables": variables,
            "is_batched": is_batched,
            "detected_fields": list(set(fields)),
            "is_introspection": is_introspection,
            "query_length": len(query),
            "security_findings": vulnerabilities
        }

class WebSocketParser:
    """
    WebSocket frame messages aur real-time traffic ko inspect karta hai.
    """
    @staticmethod
    def inspect_handshake(headers: Dict[str, str]) -> Dict[str, Any]:
        findings = []
        origin = headers.get("origin", "")
        sec_websocket_protocol = headers.get("sec-websocket-protocol")

        if not origin:
            findings.append({
                "type": "Missing Origin Header in WebSocket Handshake",
                "severity": "Medium",
                "description": "Handshake lacks an Origin header, potentially vulnerable to Cross-Site WebSocket Hijacking (CSWSH)."
            })

        return {
            "origin": origin,
            "subprotocol": sec_websocket_protocol,
            "handshake_findings": findings
        }

    @staticmethod
    def parse_message(message_data: str) -> Dict[str, Any]:
        findings = []
        try:
            # Agar message JSON format mein hai (jaise JSON-RPC / Subscriptions)
            parsed_json = json.loads(message_data)
            
            # Check karte hain ki kya koi sensitive keys hain
            sensitive_keywords = ["token", "auth", "password", "secret", "session", "credential"]
            has_sensitive_data = any(keyword in str(parsed_json).lower() for keyword in sensitive_keywords)
            
            if has_sensitive_data:
                findings.append({
                    "type": "Sensitive Data in WebSocket Frame",
                    "severity": "High",
                    "description": "Plaintext credentials or auth tokens transmitted over WebSocket message."
                })
            
            return {
                "protocol": "json",
                "payload": parsed_json,
                "has_sensitive_data": has_sensitive_data,
                "findings": findings
            }
        except json.JSONDecodeError:
            # Agar raw text ya binary frame hai
            return {
                "protocol": "raw",
                "payload": message_data,
                "length": len(message_data),
                "findings": []
            }