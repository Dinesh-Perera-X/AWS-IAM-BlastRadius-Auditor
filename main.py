import argparse
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.parser import IAMPolicyParser

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
    console.print(f"[*] Extracted [bold green]{len(statements)}[/bold green] statement blocks. Auditing wildcard boundaries...")

    findings = IAMPolicyParser.audit_wildcards(statements)

    table = Table(title="[bold cyan]🔍 IAM Policy Wildcard & Surface Exposure Findings[/bold cyan]", border_style="cyan")
    table.add_column("Statement Index", justify="center", style="dim")
    table.add_column("Issue Type", justify="center", style="magenta")
    table.add_column("Severity", justify="center")
    table.add_column("Security Finding / Anti-Pattern Description", style="yellow")

    if not findings:
        table.add_row("-", "CLEAN", "[bold green]INFORMATIONAL[/bold green]", "No full wildcards or open administrative access paths detected.")
    else:
        for f in findings:
            sev = f["severity"]
            sev_str = f"[bold red]{sev}[/bold red]" if sev == "CRITICAL" else f"[bold yellow]{sev}[/bold yellow]"
            table.add_row(
                str(f["statement_index"]),
                f["issue"],
                sev_str,
                f["description"]
            )

    console.print(table)
    console.print("\n[bold green]✔ Day 1 Complete:[/bold green] IAM syntax normalizer and wildcard detection operational.")

if __name__ == "__main__":
    main()
