import argparse
import sys
import os
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from core.parser import IAMPolicyParser
from core.boto3_collector import LiveIAMCollector
from analyzers.privesc import PrivilegeEscalationDetector
from analyzers.blast_radius import BlastRadiusScorer
from generators.synthesizer import PolicySynthesizer
from reports.reporter import BlastRadiusReporter

console = Console()

def display_banner():
    banner = (
        "[bold cyan]AWS IAM Blast Radius & Least-Privilege Auditor ☁️🛡️[/bold cyan]\n"
        "[dim]Privilege Escalation Analyzer & Automated CIEM Remediation Engine[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(
        description="Audit AWS IAM policies for privilege escalation risks, blast radius impact, and least privilege."
    )
    parser.add_argument("-p", "--policy", help="Path to local IAM policy JSON file", default="policies/compromised_dev_role.json")
    parser.add_argument("--role-name", help="Live AWS IAM Role name to audit via Boto3")
    parser.add_argument("--remediate", action="store_true", help="Synthesize and export least-privilege replacement policy")
    parser.add_argument("-o", "--output", help="Path to write remediated policy JSON", default="policies/remediated_policy.json")
    parser.add_argument("--json", help="Export audit results to JSON", default="iam_blast_radius_report.json")
    parser.add_argument("--html", help="Export visual HTML audit dossier", default="iam_blast_radius_dossier.html")
    args = parser.parse_args()

    display_banner()

    target_name = args.policy
    policy_doc = None

    if args.role_name:
        target_name = f"AWS IAM Role: {args.role_name}"
        console.print(f"[*] Querying live AWS account for IAM Role: [cyan]{args.role_name}[/cyan]...")
        policy_doc = LiveIAMCollector.fetch_role_policy(args.role_name)
        if not policy_doc:
            console.print("[dim yellow][!] Live fetch unavailable or role not found. Falling back to local policy file.[/dim yellow]")
            policy_doc = IAMPolicyParser.load_policy_file(args.policy)
    else:
        if not os.path.exists(args.policy):
            console.print(f"[red][!] Error: Policy file '{args.policy}' not found.[/red]")
            sys.exit(1)
        console.print(f"[*] Ingesting and parsing IAM Policy Document: [cyan]{args.policy}[/cyan]\n")
        policy_doc = IAMPolicyParser.load_policy_file(args.policy)

    if not policy_doc:
        console.print("[red][!] Failed to load valid JSON policy document.[/red]")
        sys.exit(1)

    statements = IAMPolicyParser.extract_statements(policy_doc)

    # 1. Wildcard Audit
    wildcard_findings = IAMPolicyParser.audit_wildcards(statements)
    w_table = Table(title="[bold cyan]🔍 Wildcard & Surface Exposure[/bold cyan]", border_style="cyan")
    w_table.add_column("Statement Index", justify="center", style="dim")
    w_table.add_column("Issue Type", justify="center", style="magenta")
    w_table.add_column("Severity", justify="center")
    w_table.add_column("Description", style="yellow")

    if not wildcard_findings:
        w_table.add_row("-", "CLEAN", "[bold green]INFORMATIONAL[/bold green]", "No unrestricted wildcard grants detected.")
    else:
        for f in wildcard_findings:
            sev_str = f"[bold red]{f['severity']}[/bold red]" if f['severity'] == "CRITICAL" else f"[bold yellow]{f['severity']}[/bold yellow]"
            w_table.add_row(str(f["statement_index"]), f["issue"], sev_str, f["description"])
    console.print(w_table)
    console.print()

    # 2. Privilege Escalation Detection
    privesc_findings = PrivilegeEscalationDetector.scan_for_privesc(statements)
    p_table = Table(title="[bold red]🚨 Viable AWS Privilege Escalation Attack Paths (MITRE ATT&CK T1548)[/bold red]", border_style="red")
    p_table.add_column("Rule ID", justify="center", style="cyan")
    p_table.add_column("Attack Vector Name", style="white")
    p_table.add_column("MITRE ID", justify="center", style="magenta")
    p_table.add_column("Severity", justify="center")
    p_table.add_column("Exploitation Mechanism", style="yellow")

    if not privesc_findings:
        p_table.add_row("-", "No PrivEsc Vectors", "N/A", "[bold green]SAFE[/bold green]", "Granted actions do not allow elevation to AdministratorAccess.")
    else:
        for p in privesc_findings:
            sev_str = f"[bold red]{p['severity']}[/bold red]" if p['severity'] == "CRITICAL" else f"[bold yellow]{p['severity']}[/bold yellow]"
            p_table.add_row(p["id"], p["name"], p["mitre_id"], sev_str, p["description"])
    console.print(p_table)
    console.print()

    # 3. Blast Radius Assessment
    radius = BlastRadiusScorer.assess_radius(statements, privesc_findings)
    score = radius["score"]
    sev = radius["severity"]
    score_color = "red" if score >= 75 else "yellow" if score >= 40 else "green"

    r_panel = Panel(
        f"[bold white]Composite Blast Radius Score:[/bold white] [{score_color}][bold]{score}/100[/bold] ({sev})[/{score_color}]\n"
        f"[dim]Data Destruction Vectors: {radius['destructive_actions_count']} | Exfiltration Vectors: {radius['exfil_actions_count']}[/dim]\n\n"
        "[bold underline]Impact Justifications:[/bold underline]\n" +
        "\n".join([f"• {factor}" for factor in radius["contributing_factors"]]),
        title="[bold cyan]💥 Credential Compromise Blast Radius Impact Analysis[/bold cyan]",
        border_style=score_color
    )
    console.print(r_panel)

    # Compile Audit Results
    audit_summary = {
        "target": target_name,
        "blast_radius": radius,
        "wildcard_findings": wildcard_findings,
        "privesc_findings": privesc_findings
    }

    # 4. Remediation Synthesizer
    if args.remediate:
        remediated_doc = PolicySynthesizer.generate_least_privilege(policy_doc, privesc_findings)
        PolicySynthesizer.export_remediated_policy(remediated_doc, args.output)
        console.print(f"\n[bold green]✔ Hardened Least-Privilege IAM Policy Synthesized:[/bold green] [cyan]{args.output}[/cyan]")

    # 5. Export Reports
    if args.json:
        BlastRadiusReporter.export_json(audit_summary, args.json)
        console.print(f"[green]✔ Structured JSON SIEM Telemetry Exported:[/green] [cyan]{args.json}[/cyan]")
    if args.html:
        BlastRadiusReporter.export_html(audit_summary, args.html)
        console.print(f"[green]✔ Visual HTML Audit Dossier Exported:[/green] [cyan]{args.html}[/cyan]")

    console.print("\n[bold green]✔ Day 5 Complete:[/bold green] AWS IAM Blast Radius & Least-Privilege Auditor fully finalized.")

if __name__ == "__main__":
    main()
