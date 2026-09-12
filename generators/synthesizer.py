import json
from typing import Dict, Any, List

class PolicySynthesizer:
    """
    Synthesizes hardened, least-privilege IAM policies by stripping
    wildcards, disarming privilege escalation vectors, and adding resource boundaries.
    """

    SAFE_DEFAULTS = [
        "ec2:Describe*",
        "s3:ListBucket",
        "s3:GetObject",
        "cloudwatch:GetMetricData",
        "logs:DescribeLogGroups"
    ]

    HIGH_RISK_PRIVESC_ACTIONS = {
        "iam:createpolicyversion", "iam:setdefaultpolicyversion",
        "iam:attachuserpolicy", "iam:attachrolepolicy",
        "iam:putuserpolicy", "iam:putrolepolicy"
    }

    @classmethod
    def generate_least_privilege(cls, original_policy: Dict[str, Any], privesc_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generates a hardened remediation IAM policy."""
        hardened_statements = []

        statements = original_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                hardened_statements.append(stmt)
                continue

            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            # 1. Neutralize full wildcard
            if "*" in actions:
                hardened_statements.append({
                    "Sid": f"HardenedStatement{idx+1}ReadOps",
                    "Effect": "Allow",
                    "Action": cls.SAFE_DEFAULTS,
                    "Resource": "*"
                })
                continue

            # 2. Filter out identified privilege escalation vectors
            cleaned_actions = []
            for act in actions:
                act_lower = act.lower()
                if act_lower in cls.HIGH_RISK_PRIVESC_ACTIONS:
                    continue
                # If passrole is present with compute, strip passrole to prevent escalation
                if act_lower == "iam:passrole" and any(p["id"] in ("PRIVESC-03", "PRIVESC-04") for p in privesc_findings):
                    continue
                cleaned_actions.append(act)

            # 3. Scope resources if wildcarded
            scoped_resources = resources
            if "*" in resources:
                scoped_resources = [
                    "arn:aws:s3:::REPLACE_WITH_SPECIFIC_BUCKET",
                    "arn:aws:s3:::REPLACE_WITH_SPECIFIC_BUCKET/*"
                ]

            if cleaned_actions:
                hardened_statements.append({
                    "Sid": f"HardenedStatement{idx+1}",
                    "Effect": "Allow",
                    "Action": cleaned_actions,
                    "Resource": scoped_resources
                })

        return {
            "Version": "2012-10-17",
            "Statement": hardened_statements
        }

    @staticmethod
    def export_remediated_policy(policy_doc: Dict[str, Any], filepath: str = "policies/remediated_policy.json") -> None:
        """Writes the hardened policy to disk."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(policy_doc, f, indent=2)
