import json
from typing import Optional, Dict, Any

class LiveIAMCollector:
    """
    Connects to live AWS accounts via Boto3 to enumerate IAM roles/users
    and extract their attached policy documents.
    """

    @staticmethod
    def fetch_role_policy(role_name: str) -> Optional[Dict[str, Any]]:
        """Extracts attached and inline policies for a live IAM role."""
        try:
            import boto3
            client = boto3.client("iam")
            
            # Fetch inline policies
            inline_names = client.list_role_policies(RoleName=role_name).get("PolicyNames", [])
            combined_statements = []

            for p_name in inline_names:
                doc = client.get_role_policy(RoleName=role_name, PolicyName=p_name).get("PolicyDocument", {})
                stmts = doc.get("Statement", [])
                if isinstance(stmts, dict):
                    stmts = [stmts]
                combined_statements.extend(stmts)

            # Fetch attached managed policies
            attached = client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
            for att in attached:
                arn = att["PolicyArn"]
                p_meta = client.get_policy(PolicyArn=arn).get("Policy", {})
                ver_id = p_meta.get("DefaultVersionId")
                if ver_id:
                    ver_doc = client.get_policy_version(PolicyArn=arn, VersionId=ver_id).get("PolicyVersion", {}).get("Document", {})
                    stmts = ver_doc.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    combined_statements.extend(stmts)

            return {
                "Version": "2012-10-17",
                "Statement": combined_statements
            }
        except Exception:
            return None
