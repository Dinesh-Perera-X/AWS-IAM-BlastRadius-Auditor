import json
import os
from typing import Dict, Any, List, Optional

class IAMPolicyParser:
    """
    Parses and normalizes AWS IAM policy documents, extracting statements,
    actions, resources, and checking for dangerous wildcard permissions.
    """

    @staticmethod
    def load_policy_file(filepath: str) -> Optional[Dict[str, Any]]:
        """Loads a JSON IAM policy file."""
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    @classmethod
    def extract_statements(cls, policy_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalizes Statement block into a list of dictionaries."""
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        return statements

    @classmethod
    def audit_wildcards(cls, statements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detects full admin wildcards and over-permissive service grants."""
        wildcard_findings = []

        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            has_admin_action = "*" in actions
            has_wildcard_resource = "*" in resources
            service_wildcards = [a for a in actions if a.endswith(":*") and a != "*"]

            if has_admin_action and has_wildcard_resource:
                wildcard_findings.append({
                    "statement_index": idx,
                    "severity": "CRITICAL",
                    "issue": "FULL_ADMIN_WILDCARD",
                    "description": "Policy grants unrestricted AdministratorAccess (Action: '*' on Resource: '*')."
                })
            elif has_admin_action:
                wildcard_findings.append({
                    "statement_index": idx,
                    "severity": "HIGH",
                    "issue": "ACTION_WILDCARD",
                    "description": "Wildcard Action '*' detected with restricted resources."
                })
            elif service_wildcards and has_wildcard_resource:
                wildcard_findings.append({
                    "statement_index": idx,
                    "severity": "HIGH",
                    "issue": "SERVICE_WILDCARD",
                    "description": f"Full service-level wildcards granted on all resources: {', '.join(service_wildcards)}"
                })

        return wildcard_findings
