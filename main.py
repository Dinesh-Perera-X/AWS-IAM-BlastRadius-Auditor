import argparse
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.parser import IAMPolicyParser
from analyzers.privesc import PrivilegeEscalationDetector
from analyzers.blast_radius import BlastRadiusScorer

console = Console()

def display_banner():
    banner = (
        "[bold cyan]AWS IAM Blast Radius & Least-Privilege Auditor ☁️🛡️[/bold cyan]\n"
        "[dim]Privilege Escalation Analyzer & Automated CIEM Remediation Engine[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(
        description="Audit AWS IAM policies for privilege escalation risks and wildcard anti-patterns."
    )
    parser.add_argument("-p", "--policy", help="Path to local IAM policy JSON file", default="policies/compromised_dev_role.json")
    args = parser.parse_args()

    display_banner()

    if not os.path.exists(args.policy):
        console.print(f"[red][!] Error: Policy file '{args.policy}' not found.[/red]")
        sys.exit(1)

    console.print(f"[*] Ingesting and parsing IAM Policy Document: [cyan]{args.policy}[/cyan]\n")

    policy_doc = IAMPolicyParser.load_policy_file(args.policy)
    if not policy_doc:
        console.print("[red][!] Failed to parse JSON policy document.[/red]")
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

    console.print("\n[bold green]✔ Day 3 Complete:[/bold green] Blast radius calculation engine and impact assessment verified.")

if __name__ == "__main__":
    main()
