from typing import List, Dict, Any, Set

class BlastRadiusScorer:
    """
    Computes a quantitative Blast Radius Score (0-100) and assesses
    data destruction, exfiltration, and lateral movement risks.
    """

    DESTRUCTIVE_ACTIONS = {
        "s3:deletebucket", "s3:deleteobject", "rds:deletedbinstance",
        "dynamodb:deletetable", "kms:schedulekeydeletion", "ec2:terminateinstances"
    }

    EXFILTRATION_ACTIONS = {
        "s3:getobject", "secretsmanager:getsecretvalue", "ssm:getparameter",
        "ssm:getparameters", "kms:decrypt"
    }

    @classmethod
    def extract_action_set(cls, statements: List[Dict[str, Any]]) -> Set[str]:
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
    def assess_radius(cls, statements: List[Dict[str, Any]], privesc_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        actions = cls.extract_action_set(statements)
        score = 0
        factors = []

        # 1. Full Admin Wildcard Check (+50)
        if "*" in actions:
            score += 50
            factors.append("Global wildcard '*' grants unrestricted control across all AWS services.")

        # 2. Privilege Escalation Paths (+30 max)
        if privesc_findings:
            escalation_penalty = min(30, len(privesc_findings) * 15)
            score += escalation_penalty
            factors.append(f"Contains {len(privesc_findings)} exploitable privilege escalation attack paths.")

        # 3. Data Destruction Exposure (+15 max)
        destructive_matched = [a for a in cls.DESTRUCTIVE_ACTIONS if a in actions or a.split(":")[0] + ":*" in actions or "*" in actions]
        if destructive_matched:
            dest_points = min(15, len(destructive_matched) * 3)
            score += dest_points
            factors.append(f"Grants {len(destructive_matched)} data destruction permissions (e.g., bucket/DB deletion).")

        # 4. Sensitive Credential / Data Exfiltration (+15 max)
        exfil_matched = [a for a in cls.EXFILTRATION_ACTIONS if a in actions or a.split(":")[0] + ":*" in actions or "*" in actions]
        if exfil_matched:
            exfil_points = min(15, len(exfil_matched) * 3)
            score += exfil_points
            factors.append(f"Grants access to sensitive data exfiltration vectors (Secrets Manager/SSM/S3).")

        # 5. Lateral Movement & Cross-Account Role Assumption (+10)
        if "sts:assumerole" in actions or "sts:*" in actions or "*" in actions:
            score += 10
            factors.append("Permissions include sts:AssumeRole for cross-account lateral movement.")

        final_score = min(100, score)

        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 50:
            severity = "HIGH"
        elif final_score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "score": final_score,
            "severity": severity,
            "destructive_actions_count": len(destructive_matched),
            "exfil_actions_count": len(exfil_matched),
            "contributing_factors": factors
        }
