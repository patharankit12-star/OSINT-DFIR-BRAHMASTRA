from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.database import CaseDatabase
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

    # 1. Open or create the isolated SQLite database for this case
    db = CaseDatabase(case_name=case)
    extractor = DFIRExtractor(db=db)

    try:
        # 2. Run the 4-layer forensic extraction with a live loading spinner
        with console.status(f"[bold green]Scanning artifact: {file}...[/bold green]", spinner="dots"):
            result = extractor.analyze_file(file)

        # 3. Display Artifact Summary Panel (Hashes & Chain of Custody)
        summary_text = (
            f"[bold white]Case DB:[/bold white] cases/{case}.db\n"
            f"[bold white]File Name:[/bold white] {result['file_name']} ({result['file_size']} bytes)\n"
            f"[bold white]MD5:[/bold white] {result['hashes']['md5']}\n"
            f"[bold white]SHA-256:[/bold white] {result['hashes']['sha256']}"
        )
        console.print(Panel(summary_text, title="[bold green]Forensic Artifact Locked[/bold green]", border_style="green"))

        # 4. Display Secrets Table (Telegram Bots, Discord Webhooks, API Keys)
        if result["secrets"]:
            secret_table = Table(title="Discovered Secrets & C2 Credentials", border_style="red")
            secret_table.add_column("Secret Type", style="bold red")
            secret_table.add_column("Value", style="yellow")
            for s in result["secrets"]:
                secret_table.add_row(s["type"], s["value"])
            console.print(secret_table)
        else:
            console.print("[dim]No leaked secrets or C2 tokens found.[/dim]")

        # 5. Display IOCs Table (Emails, URLs, IPs, Local Paths, Crypto Wallets)
        if result["iocs"]:
            ioc_table = Table(title="Extracted IOCs & Attribution Leads", border_style="magenta")
            ioc_table.add_column("IOC Type", style="bold magenta")
            ioc_table.add_column("Value", style="cyan")
            for ioc in result["iocs"]:
                ioc_table.add_row(ioc["type"], ioc["value"])
            console.print(ioc_table)
        else:
            console.print("[dim]No regex IOCs found.[/dim]")

        # 6. Display Top ExifTool Metadata Tags (limit to 15 rows for clean terminal view)
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
        # Always close the database connection cleanly
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