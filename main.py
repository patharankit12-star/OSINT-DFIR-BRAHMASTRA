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
from modules.graph_builder import GraphBuilder
from modules.report_generator import ReportGenerator

app = typer.Typer(help="OSINT-DFIR-BRAHMASTRA: Unified Forensic & OSINT Automation Framework")
console = Console()


def _display_grouped_osint_table(db: CaseDatabase, case: str, target: str, title_prefix: str):
    """Helper to display OSINT findings grouped by tool with a 1-line spacer between tools."""
    all_findings = db.get_all_osint_findings()
    target_clean = target.strip().lower().lstrip("@")
    findings = [
        f for f in all_findings
        if f["target"].lower() == target_clean or target_clean in f["target"].lower()
    ]

    tool_order = [
        "whois", "dns", "crt.sh", "virustotal", "hunter_io",
        "phone_osint",
        "email_hygiene", "xposedornot", "gravatar", "github_search", "holehe",
        "username_scan", "github_api", "github_patch", "sherlock",
    ]

    grouped = {}
    for f in findings:
        grouped.setdefault(f["source_tool"], []).append(f)

    table = Table(title=f"{title_prefix}: {target} (Case: {case})", border_style="cyan")
    table.add_column("Source Tool", style="bold yellow")
    table.add_column("Field / Type", style="bold magenta")
    table.add_column("Extracted Value", style="green")

    added_sections = 0
    ordered_tools = [t for t in tool_order if t in grouped] + [t for t in grouped if t not in tool_order]

    for tool_name in ordered_tools:
        if added_sections > 0:
            table.add_row("", "", "")
        for idx, item in enumerate(grouped[tool_name]):
            label = tool_name.upper() if idx == 0 else ""
            table.add_row(label, item["finding_type"], item["finding_value"])
        added_sections += 1

    if added_sections > 0:
        console.print(table)
    else:
        console.print("[yellow]No OSINT findings returned for this target.[/yellow]")


@app.command()
def analyze(
    case: str = typer.Option(..., "--case", "-c", help="Name of the investigation case (e.g., case_01)"),
    file: str = typer.Option(..., "--file", "-f", help="Path to the suspicious file to analyze"),
):
    """Engine 1: Run full DFIR artifact extraction (Hashes, ExifTool, Gitleaks, IOCs) on a file."""
    console.print(Panel.fit("[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold yellow]Engine 1: DFIR Artifact Extractor[/bold yellow]", border_style="cyan"))

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

        if result["iocs"]:
            ioc_table = Table(title="Extracted IOCs & Attribution Leads", border_style="magenta")
            ioc_table.add_column("IOC Type", style="bold magenta")
            ioc_table.add_column("Value", style="cyan")
            for ioc in result["iocs"]:
                ioc_table.add_row(ioc["type"], ioc["value"])
            console.print(ioc_table)

        if result["metadata"]:
            meta_table = Table(title=f"ExifTool Metadata (Total: {result['metadata_count']} tags)", border_style="blue")
            meta_table.add_column("Tag Name", style="bold blue")
            meta_table.add_column("Value", style="white")
            for key, val in list(result["metadata"].items())[:15]:
                meta_table.add_row(str(key), str(val))
            console.print(meta_table)

        console.print(f"\n[bold green]✔ Extraction complete! All evidence saved to cases/{case}.db[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        db.close()


@app.command()
def recon(
    case: str = typer.Option(..., "--case", "-c", help="Name of the investigation case"),
    target: str = typer.Option(..., "--target", "-t", help="Target Domain, Email, Username, or Phone"),
    target_type: Optional[str] = typer.Option(None, "--type", help="Optional: DOMAIN, EMAIL, USERNAME, or PHONE"),
):
    """Engine 2: Run direct OSINT recon on a Domain (WHOIS, DNS, crt.sh, VT, Hunter)."""
    console.print(Panel.fit("[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold yellow]Engine 2: OSINT Recon[/bold yellow]", border_style="cyan"))

    if not target_type:
        if "@" in target:
            target_type = "EMAIL"
        elif target.startswith("+") or target.replace(" ", "").replace("-", "").isdigit():
            target_type = "PHONE"
        elif "." in target:
            target_type = "DOMAIN"
        else:
            target_type = "USERNAME"

    db = CaseDatabase(case_name=case)
    orchestrator = AutoPivotOrchestrator(db=db, config=ConfigManager(), console=console)
    try:
        with console.status(f"[bold green]Running {target_type} recon on {target}...[/bold green]", spinner="dots"):
            orchestrator.run_single_recon(target, target_type)
        _display_grouped_osint_table(db, case, target, "OSINT Recon Report")
        console.print(f"\n[bold green]✔ Recon complete! Saved to cases/{case}.db[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        db.close()


@app.command()
def phone(
    case: str = typer.Option(..., "--case", "-c", help="Name of the investigation case"),
    number: str = typer.Option(..., "--phone", "-p", help="Target phone number (e.g., +919876543210)"),
):
    """Engine 3: Run Mobile Number OSINT (Carrier, Location, VoIP check, WhatsApp/Telegram & Google Dorks)."""
    console.print(Panel.fit("[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold yellow]Engine 3: Mobile Number OSINT[/bold yellow]", border_style="cyan"))

    db = CaseDatabase(case_name=case)
    orchestrator = AutoPivotOrchestrator(db=db, config=ConfigManager(), console=console)
    try:
        with console.status(f"[bold green]Analyzing phone number {number}...[/bold green]", spinner="dots"):
            res = orchestrator.run_single_recon(number, "PHONE")
        lookup_key = res.get("e164", number)
        _display_grouped_osint_table(db, case, lookup_key, "Phone OSINT Report")
        console.print(f"\n[bold green]✔ Phone OSINT complete! Saved to cases/{case}.db[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        db.close()


@app.command()
def email(
    case: str = typer.Option(..., "--case", "-c", help="Name of the investigation case"),
    address: str = typer.Option(..., "--email", "-e", help="Target email address"),
):
    """Engine 3: Run Deep Email OSINT (MX/Disposable, XposedOrNot Breaches, Gravatar, GitHub, Holehe)."""
    console.print(Panel.fit("[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold yellow]Engine 3: Email OSINT[/bold yellow]", border_style="cyan"))

    db = CaseDatabase(case_name=case)
    orchestrator = AutoPivotOrchestrator(db=db, config=ConfigManager(), console=console)
    try:
        with console.status(f"[bold green]Running deep email OSINT on {address}...[/bold green]", spinner="dots"):
            orchestrator.run_single_recon(address, "EMAIL")
        _display_grouped_osint_table(db, case, address, "Email OSINT Report")
        console.print(f"\n[bold green]✔ Email OSINT complete! Saved to cases/{case}.db[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        db.close()


@app.command()
def username(
    case: str = typer.Option(..., "--case", "-c", help="Name of the investigation case"),
    user: str = typer.Option(..., "--username", "-u", help="Target username / handle"),
):
    """Engine 3: Run Deep Username OSINT (Multi-platform scan, GitHub .patch carving, Sherlock)."""
    console.print(Panel.fit("[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold yellow]Engine 3: Username OSINT[/bold yellow]", border_style="cyan"))

    db = CaseDatabase(case_name=case)
    orchestrator = AutoPivotOrchestrator(db=db, config=ConfigManager(), console=console)
    try:
        with console.status(f"[bold green]Scanning platforms & GitHub for '{user}'...[/bold green]", spinner="dots"):
            orchestrator.run_single_recon(user, "USERNAME")
        _display_grouped_osint_table(db, case, user, "Username OSINT Report")
        console.print(f"\n[bold green]✔ Username OSINT complete! Saved to cases/{case}.db[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        db.close()


@app.command()
def autopivot(
    case: str = typer.Option(..., "--case", "-c", help="Name of the existing investigation case"),
    depth: int = typer.Option(2, "--depth", "-d", help="How many AI pivot levels deep to investigate (1-3)"),
):
    """Engine 2 (AI Brain): Autonomously analyze case DB with Gemini AI and pivot to new OSINT targets."""
    console.print(Panel.fit("[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold magenta]Autonomous AI Pivot Brain[/bold magenta]", border_style="magenta"))

    db = CaseDatabase(case_name=case)
    orchestrator = AutoPivotOrchestrator(db=db, config=ConfigManager(), console=console)
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
    """List all existing SQLite investigation cases stored in the cases/ directory."""
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

@app.command()
def report(
    case: str = typer.Option(..., "--case", "-c", help="Name of the investigation case (e.g., master_case_01)"),
):
    """Engine 4: Generate Interactive Mini-Maltego HTML Graph and Court-Ready Forensic Report."""
    console.print(
        Panel.fit(
            "[bold cyan]OSINT-DFIR-BRAHMASTRA[/bold cyan] | [bold green]Engine 4: Visual Graph & Forensic Report[/bold green]",
            border_style="green",
        )
    )

    db_path = Path("cases") / f"{case}.db"
    if not db_path.exists():
        console.print(f"[bold red]Error:[/bold red] Case database '{db_path}' nahi mila. Pehle koi scan run karein.")
        raise typer.Exit(code=1)

    db = CaseDatabase(case_name=case)
    try:
        # 1. Build Interactive Mini-Maltego HTML Graph
        with console.status("[bold cyan]Building Mini-Maltego Interactive Graph...[/bold cyan]", spinner="dots"):
            graph_builder = GraphBuilder(db=db, case_name=case)
            graph_res = graph_builder.build_graph()

        # 2. Generate Court-Ready Forensic HTML Report (linked to the graph)
        with console.status("[bold green]Generating Court-Ready Forensic HTML Report...[/bold green]", spinner="dots"):
            report_gen = ReportGenerator(db=db, case_name=case)
            graph_filename = Path(graph_res["graph_path"]).name
            report_res = report_gen.generate_report(graph_filename=graph_filename)

        # 3. Display Summary Panel
        summary = (
            f"[bold white]Case ID:[/bold white] {case}\n"
            f"[bold cyan]Interactive Graph:[/bold cyan] {graph_res['graph_path']} "
            f"([yellow]{graph_res['nodes']} nodes, {graph_res['edges']} edges[/yellow])\n"
            f"[bold green]Forensic Report:[/bold green] {report_res['report_path']}\n"
            f"[bold white]Stats:[/bold white] {report_res['artifacts']} Artifacts | "
            f"{report_res['alerts']} Critical Alerts | {report_res['osint_findings']} OSINT Findings"
        )
        console.print(Panel(summary, title="[bold green]Phase 4 Deliverables Ready[/bold green]", border_style="green"))
        console.print(f"\n[bold yellow]Tip:[/bold yellow] open in Browser : [bold cyan]xdg-open {report_res['report_path']}[/bold cyan]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    finally:
        db.close()

if __name__ == "__main__":
    app()