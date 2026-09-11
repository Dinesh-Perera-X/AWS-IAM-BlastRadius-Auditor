# AWS IAM Blast Radius & Least-Privilege Auditor ☁️🛡️

A Cloud Infrastructure Entitlement Management (CIEM) and privilege escalation analysis tool built in Python. Audits AWS IAM roles, calculates blast radius impact scores, detects dangerous permission chains (`iam:PassRole`, `lambda:CreateFunction`), and synthesizes least-privilege replacement policies.

---

## 🎯 5-Day Development Roadmap

- [x] **Day 1: Project Setup, IAM Normalizer & Wildcard Audit Engine**
- [x] **Day 2: Privilege Escalation Attack Vector Detection Matrix**
- [x] **Day 3: Quantitative Blast Radius Impact & Data Exposure Scorer**
- [ ] **Day 4: Automated Least-Privilege Scoped Policy Synthesizer**
- [ ] **Day 5: Live AWS Account Boto3 Ingestion, Interactive UI & HTML Audit Report**

---

## 🚀 Key Capabilities
* **Wildcard & Anti-Pattern Detection:** Identifies full admin grants (`*` on `*`) and unbounded service wildcards (`s3:*`, `iam:*`).
* **Privilege Escalation Mapping:** Analyzes 21+ AWS permission combinations allowing attackers to escalate from developer roles to Full Administrator.
* **Blast Radius Quantification:** Scores the potential damage of a compromised credential across data destruction, lateral movement, and infrastructure manipulation.
* **Automated Least-Privilege Synthesis:** Automatically generates tightened JSON policies stripping unused and high-risk actions.

---

## 📦 Installation & Setup

```bash
git clone [https://github.com/Dinesh-Perera-X/AWS-IAM-BlastRadius-Auditor.git](https://github.com/Dinesh-Perera-X/AWS-IAM-BlastRadius-Auditor.git)
cd AWS-IAM-BlastRadius-Auditor
pip3 install -r requirements.txt --break-system-packages
