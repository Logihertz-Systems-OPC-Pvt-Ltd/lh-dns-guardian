# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.exporters.table
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Rich terminal table finding exporter."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lh_dns_guardian.exporters.base import BaseExporter
from lh_dns_guardian.models import AuditReport, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "bold cyan",
}


class TableExporter(BaseExporter):
    """Renders audit findings into an attractive Rich terminal table."""

    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize table exporter with optional console."""
        self.console = console or Console()

    def export(self, report: AuditReport, output_file: Optional[str] = None) -> str:
        """Render findings to a formatted table string and optionally write to disk."""
        string_io = io.StringIO()
        render_console = Console(file=string_io, width=130, force_terminal=False, color_system=None)

        # Header summary panel
        summary = report.summary_counts()
        summary_text = (
            f"[bold]Target:[/bold] {report.target} ({report.target_type})\n"
            f"[bold]Timestamp:[/bold] {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"[bold]Total Findings:[/bold] {len(report.findings)} "
            f"([red]Critical: {summary.get('CRITICAL', 0)}[/red] | "
            f"[bright_red]High: {summary.get('HIGH', 0)}[/bright_red] | "
            f"[yellow]Medium: {summary.get('MEDIUM', 0)}[/yellow] | "
            f"[blue]Low: {summary.get('LOW', 0)}[/blue] | "
            f"[cyan]Info: {summary.get('INFO', 0)}[/cyan])"
        )
        panel = Panel(summary_text, title="lh-dns-guardian Security Posture Report", expand=False)
        render_console.print(panel)

        table = Table(
            title="Audit Findings",
            show_header=True,
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Rule ID", style="dim", width=12)
        table.add_column("Severity", width=10, justify="center")
        table.add_column("Category", width=14)
        table.add_column("Target", width=22)
        table.add_column("Finding Title", width=28)
        table.add_column("Recommendation", min_width=30)

        # Sort findings by severity rank descending
        sorted_findings = sorted(report.findings, key=lambda f: f.severity.rank, reverse=True)

        for finding in sorted_findings:
            sev_style = SEVERITY_STYLES.get(finding.severity, "white")
            table.add_row(
                finding.id,
                f"[{sev_style}]{finding.severity.value}[/{sev_style}]",
                finding.category.value,
                finding.target,
                finding.title,
                finding.recommendation,
            )

        render_console.print(table)
        output_str = string_io.getvalue()

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output_str)

        return output_str

    def display(self, report: AuditReport) -> None:
        """Print rich colored table directly to the active terminal console."""
        summary = report.summary_counts()
        summary_text = (
            f"[bold]Target:[/bold] {report.target} ({report.target_type})\n"
            f"[bold]Timestamp:[/bold] {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"[bold]Total Findings:[/bold] {len(report.findings)} "
            f"(Critical: {summary.get('CRITICAL', 0)} | "
            f"High: {summary.get('HIGH', 0)} | "
            f"Medium: {summary.get('MEDIUM', 0)} | "
            f"Low: {summary.get('LOW', 0)} | "
            f"Info: {summary.get('INFO', 0)})"
        )
        panel = Panel(
            summary_text,
            title="[bold cyan]lh-dns-guardian Security Posture Report[/bold cyan]",
            expand=False,
        )
        self.console.print(panel)

        table = Table(
            title="Audit Findings",
            show_header=True,
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Rule ID", style="dim", width=12)
        table.add_column("Severity", width=10, justify="center")
        table.add_column("Category", width=14)
        table.add_column("Target", width=22)
        table.add_column("Finding Title", width=28)
        table.add_column("Recommendation", min_width=30)

        sorted_findings = sorted(report.findings, key=lambda f: f.severity.rank, reverse=True)

        for finding in sorted_findings:
            sev_style = SEVERITY_STYLES.get(finding.severity, "white")
            table.add_row(
                finding.id,
                f"[{sev_style}]{finding.severity.value}[/{sev_style}]",
                finding.category.value,
                finding.target,
                finding.title,
                finding.recommendation,
            )

        self.console.print(table)
