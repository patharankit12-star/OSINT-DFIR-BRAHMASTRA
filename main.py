from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import ConfigManager
from core.database import CaseDatabase
from core.orchestrator import AutoPivotOrchestrator
from modules.dfir_extractor import DFIRExtractor

# Initialize Typer CLI app and Rich console for styled output
app = typer.Typer(help="OSINT-DFIR-BRAHMASTRA: Unified Forensic & OSINT Automation Framework")
console = Console()


@app.command()
def analyze(
    case: str = typer.Option(..., "--case", "-c", help="Name of the investigation case (e.g., case_01)"),
    file: str = typer.Option(..., "--file", "-f", help="Path to the suspicious file to analyze"),
):
    """
    Engine 1: Run full DFIR artifact extraction (Hashes, ExifTool, Gitleaks, IOCs) on a file.
    """
    console.print(
        Panel.fit(
            "[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold yellow]Engine 1: DFIR Artifact Extractor[/bold yellow]",
            border_style="cyan",
        )
    )

    db = CaseDatabase(case_name=case)
    extractor = DFIRExtractor(db=db)

    try:
        with console.status(f"[bold green]Scanning artifact: {file}...[/bold green]", spinner="dots"):
            result = extractor.analyze_file(file)

        summary_text = (
            f"[bold white]Case DB:[/bold white] cases/{case}.db\n"
            f"[bold white]File Name:[/bold white] {result['file_name']} ({result['file_size']} bytes)\n"
            f"[bold white]MD5:[/bold white] {result['hashes']['md5']}\n"
            f"[bold white]SHA-256:[/bold white] {result['hashes']['sha256']}"
        )
        console.print(Panel(summary_text, title="[bold green]Forensic Artifact Locked[/bold green]", border_style="green"))

        if result["secrets"]:
            secret_table = Table(title="Discovered Secrets & C2 Credentials", border_style="red")
            secret_table.add_column("Secret Type", style="bold red")
            secret_table.add_column("Value", style="yellow")
            for s in result["secrets"]:
                secret_table.add_row(s["type"], s["value"])
            console.print(secret_table)
        else:
            console.print("[dim]No leaked secrets or C2 tokens found.[/dim]")

        if result["iocs"]:
            ioc_table = Table(title="Extracted IOCs & Attribution Leads", border_style="magenta")
            ioc_table.add_column("IOC Type", style="bold magenta")
            ioc_table.add_column("Value", style="cyan")
            for ioc in result["iocs"]:
                ioc_table.add_row(ioc["type"], ioc["value"])
            console.print(ioc_table)
        else:
            console.print("[dim]No regex IOCs found.[/dim]")

        if result["metadata"]:
            meta_table = Table(title=f"ExifTool Metadata (Total: {result['metadata_count']} tags)", border_style="blue")
            meta_table.add_column("Tag Name", style="bold blue")
            meta_table.add_column("Value", style="white")
            for key, val in list(result["metadata"].items())[:15]:
                meta_table.add_row(str(key), str(val))
            console.print(meta_table)

        console.print(f"\n[bold green]✔ Extraction complete! All evidence saved to cases/{case}.db[/bold green]")

    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    except Exception as e:
        console.print(f"[bold red]Unexpected Error:[/bold red] {e}")
    finally:
        db.close()


@app.command()
def recon(
    case: str = typer.Option(..., "--case", "-c", help="Name of the investigation case"),
    target: str = typer.Option(..., "--target", "-t", help="Target Domain, Email, or Username"),
    target_type: Optional[str] = typer.Option(
        None, "--type", help="Optional: DOMAIN, EMAIL, or USERNAME (auto-detected if omitted)"
    ),
):
    """
    Engine 2: Run direct OSINT recon (WHOIS, DNS, crt.sh, VT, Hunter, GitHub .patch) on a target.
    """
    console.print(
        Panel.fit(
            "[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold yellow]Engine 2: OSINT Recon[/bold yellow]",
            border_style="cyan",
        )
    )

    # Auto-detect target type if not explicitly provided
    if not target_type:
        if "@" in target:
            target_type = "EMAIL"
        elif "." in target:
            target_type = "DOMAIN"
        else:
            target_type = "USERNAME"

    db = CaseDatabase(case_name=case)
    config = ConfigManager()
    orchestrator = AutoPivotOrchestrator(db=db, config=config, console=console)

    try:
        with console.status(f"[bold green]Running {target_type} recon on {target}...[/bold green]", spinner="dots"):
            orchestrator.run_single_recon(target, target_type)

        # Display all OSINT findings saved for this target
        findings = db.get_all_osint_findings()
        table = Table(title=f"OSINT Findings in Case: {case}", border_style="cyan")
        table.add_column("Target", style="bold white")
        table.add_column("Source", style="yellow")
        table.add_column("Type", style="magenta")
        table.add_column("Value", style="green")

        for f in findings[-30:]:  # Show latest 30 findings for clean output
            table.add_row(f["target"], f["source_tool"], f["finding_type"], f["finding_value"])
        console.print(table)
        console.print(f"\n[bold green]✔ Recon complete! Saved to cases/{case}.db[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        db.close()


@app.command()
def autopivot(
    case: str = typer.Option(..., "--case", "-c", help="Name of the existing investigation case"),
    depth: int = typer.Option(2, "--depth", "-d", help="How many AI pivot levels deep to investigate (1-3)"),
):
    """
    Engine 2 (AI Brain): Autonomously analyze case DB with Gemini AI and pivot to new OSINT targets.
    """
    console.print(
        Panel.fit(
            "[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold magenta]Autonomous AI Pivot Brain[/bold magenta]",
            border_style="magenta",
        )
    )

    db = CaseDatabase(case_name=case)
    config = ConfigManager()
    orchestrator = AutoPivotOrchestrator(db=db, config=config, console=console)

    try:
        result = orchestrator.run_autopivot(max_depth=depth)

        if result["executed_pivots"]:
            pivot_table = Table(title="Executed AI Pivots", border_style="magenta")
            pivot_table.add_column("Depth", style="cyan")
            pivot_table.add_column("Type", style="yellow")
            pivot_table.add_column("Target", style="bold green")
            pivot_table.add_column("AI Reasoning", style="white")
            for p in result["executed_pivots"]:
                pivot_table.add_row(str(p["depth"]), p["type"], p["target"], p["reason"])
            console.print(pivot_table)

        console.print(f"\n[bold green]✔ AI Auto-Pivot complete! Full intel saved in cases/{case}.db[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        db.close()


@app.command(name="list-cases")
def list_cases():
    """
    List all existing SQLite investigation cases stored in the cases/ directory.
    """
    cases_dir = Path("cases")
    db_files = list(cases_dir.glob("*.db")) if cases_dir.exists() else []

    if not db_files:
        console.print("[yellow]No investigation cases found yet.[/yellow]")
        return

    table = Table(title="Active Investigation Cases", border_style="cyan")
    table.add_column("Case Name", style="bold cyan")
    table.add_column("Database Path", style="white")
    for db_file in db_files:
        table.add_row(db_file.stem, str(db_file))
    console.print(table)


if __name__ == "__main__":
    app()