from typing import List, Dict, Any, Set

class PrivilegeEscalationDetector:
    """
    Analyzes granted AWS IAM action sets against documented AWS
    privilege escalation methods (Rhino Security Labs / MITRE ATT&CK T1548).
    """

    PRIVESC_RULES = [
        {
            "id": "PRIVESC-01",
            "name": "IAM CreatePolicyVersion Escalation",
            "required_actions": ["iam:createpolicyversion"],
            "severity": "CRITICAL",
            "mitre_id": "T1098",
            "description": "Can create a new version of an attached IAM policy granting full AdministratorAccess."
        },
        {
            "id": "PRIVESC-02",
            "name": "IAM SetDefaultPolicyVersion Escalation",
            "required_actions": ["iam:setdefaultpolicyversion"],
            "severity": "HIGH",
            "mitre_id": "T1098",
            "description": "Can switch the active default policy version to a previous, over-permissive iteration."
        },
        {
            "id": "PRIVESC-03",
            "name": "PassRole to EC2 Compute",
            "required_actions": ["iam:passrole", "ec2:runinstances"],
            "severity": "CRITICAL",
            "mitre_id": "T1548",
            "description": "Can spawn an EC2 instance with a high-privilege IAM instance profile and extract credentials."
        },
        {
            "id": "PRIVESC-04",
            "name": "PassRole to Serverless Lambda",
            "required_actions": ["iam:passrole", "lambda:createfunction", "lambda:invokefunction"],
            "severity": "CRITICAL",
            "mitre_id": "T1548",
            "description": "Can create and invoke a Lambda with an administrative execution role to exfiltrate root credentials."
        },
        {
            "id": "PRIVESC-05",
            "name": "Direct Policy Attachment",
            "required_actions": ["iam:attachuserpolicy"],
            "severity": "CRITICAL",
            "mitre_id": "T1098",
            "description": "Can directly attach AdministratorAccess to the current calling IAM user."
        },
        {
            "id": "PRIVESC-06",
            "name": "Inline Policy Injection",
            "required_actions": ["iam:putuserpolicy"],
            "severity": "CRITICAL",
            "mitre_id": "T1098",
            "description": "Can insert an inline policy directly into the user account with Action: '*' on Resource: '*'."
        },
        {
            "id": "PRIVESC-07",
            "name": "Login Profile Creation (Console Access)",
            "required_actions": ["iam:createloginprofile"],
            "severity": "HIGH",
            "mitre_id": "T1078.004",
            "description": "Can create a console password for any user without active console access."
        }
    ]

    @classmethod
    def extract_action_set(cls, statements: List[Dict[str, Any]]) -> Set[str]:
        """Extracts normalized, lowercase action strings granted with Allow effect."""
        granted = set()
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                granted.add(a.lower())
        return granted

    @classmethod
    def scan_for_privesc(cls, statements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identifies all viable privilege escalation chains within the policy."""
        granted_actions = cls.extract_action_set(statements)
        escalation_paths = []

        # If full admin wildcard is granted, all privesc paths are inherently open
        if "*" in granted_actions:
            return [{
                "id": "PRIVESC-ROOT",
                "name": "Full Unrestricted Administrator",
                "severity": "CRITICAL",
                "mitre_id": "T1078.004",
                "matched_actions": ["*"],
                "description": "Identity has global wildcard '*'. Inherently has all privilege escalation avenues."
            }]

        for rule in cls.PRIVESC_RULES:
            required = rule["required_actions"]
            # Check if all required actions are present or covered by wildcards
            matched = []
            for req in required:
                req_service = req.split(":")[0] + ":*"
                if req in granted_actions or req_service in granted_actions or "*" in granted_actions:
                    matched.append(req)

            if len(matched) == len(required):
                escalation_paths.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "mitre_id": rule["mitre_id"],
                    "matched_actions": matched,
                    "description": rule["description"]
                })

        return escalation_paths
