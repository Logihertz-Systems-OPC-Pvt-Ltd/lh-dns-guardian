# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command Line Interface for lh-dns-guardian."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from lh_dns_guardian import __version__
from lh_dns_guardian.auditor import DomainAuditor
from lh_dns_guardian.exporters.json_exporter import JsonExporter
from lh_dns_guardian.exporters.sarif import SarifExporter
from lh_dns_guardian.exporters.table import TableExporter
from lh_dns_guardian.models import AuditReport

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-dns",
    help="Domain name resolution and DNS security posture validator by Logihertz Systems.",
    add_completion=False,
)
console = Console()


class OutputFormat(str, Enum):
    """Supported output serialization formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


def version_callback(value: bool) -> None:
    """Print the application version and exit."""
    if value:
        console.print(
            f"[bold cyan]lh-dns-guardian[/bold cyan] version [bold green]{__version__}[/bold green]"
        )
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show application version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """lh-dns: DNS security posture audit and dangling takeover detection tool."""
    pass


def _output_report(
    report: AuditReport,
    fmt: OutputFormat,
    output_path: Optional[Path],
) -> None:
    """Export and render report based on selected format and output destination."""
    out_str_path = str(output_path) if output_path else None

    if fmt == OutputFormat.JSON:
        exporter = JsonExporter()
        content = exporter.export(report, output_file=out_str_path)
        if not output_path:
            typer.echo(content)
        else:
            console.print(f"[green]Successfully exported JSON report to {output_path}[/green]")

    elif fmt == OutputFormat.SARIF:
        sarif_exporter = SarifExporter()
        content = sarif_exporter.export(report, output_file=out_str_path)
        if not output_path:
            typer.echo(content)
        else:
            console.print(f"[green]Successfully exported SARIF report to {output_path}[/green]")

    else:  # TABLE
        tbl_exporter = TableExporter(console=console)
        if output_path:
            tbl_exporter.export(report, output_file=out_str_path)
            console.print(f"[green]Successfully exported table report to {output_path}[/green]")
        else:
            tbl_exporter.display(report)


@app.command("audit-domain")
def audit_domain_cmd(
    domain: Annotated[str, typer.Argument(help="Domain name to audit (e.g. example.com).")],
    nameserver: Annotated[
        str,
        typer.Option("--nameserver", "-n", help="Nameserver IP to query."),
    ] = "8.8.8.8",
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Output report format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="File path to save the generated report.",
        ),
    ] = None,
) -> None:
    """Audit live domain for DNSSEC, CAA, AXFR exposure, SPF, and DMARC posture."""
    auditor = DomainAuditor()
    report = auditor.audit_domain(domain=domain, nameserver=nameserver)
    _output_report(report, format, output)


@app.command("audit-zone")
def audit_zone_cmd(
    zonefile: Annotated[
        Path,
        typer.Argument(help="Path to BIND master zone file.", exists=True, readable=True),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Output report format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="File path to save the generated report.",
        ),
    ] = None,
) -> None:
    """Audit a BIND master zone file for DNS security configurations and dangling CNAMEs."""
    auditor = DomainAuditor()
    try:
        report = auditor.audit_zone(zone_file=zonefile)
    except Exception as exc:
        console.print(f"[bold red]Error parsing zone file {zonefile}:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    _output_report(report, format, output)


@app.command("check-takeover")
def check_takeover_cmd(
    subdomains_file: Annotated[
        Path,
        typer.Argument(
            help="Path to text file containing target subdomains (one per line).",
            exists=True,
            readable=True,
        ),
    ],
    nameserver: Annotated[
        str,
        typer.Option("--nameserver", "-n", help="Nameserver IP to query."),
    ] = "8.8.8.8",
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            case_sensitive=False,
            help="Output report format (table, json, sarif).",
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="File path to save the generated report.",
        ),
    ] = None,
) -> None:
    """Scan subdomains for dangling CNAME and NS records pointing to vulnerable cloud providers."""
    try:
        with open(subdomains_file, "r", encoding="utf-8") as f:
            subdomains = [
                line.strip() for line in f if line.strip() and not line.strip().startswith("#")
            ]
    except Exception as exc:
        console.print(
            f"[bold red]Error reading subdomains file {subdomains_file}:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    auditor = DomainAuditor()
    report = auditor.check_takeover(subdomains=subdomains, nameserver=nameserver)
    _output_report(report, format, output)


if __name__ == "__main__":
    app()
