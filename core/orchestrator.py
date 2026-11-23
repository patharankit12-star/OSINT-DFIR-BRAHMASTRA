from typing import Any, Dict, List
from rich.console import Console

from core.ai_brain import AIBrain
from core.config import ConfigManager
from core.database import CaseDatabase
from modules.domain_recon import DomainRecon
from modules.identity_recon import IdentityRecon


class AutoPivotOrchestrator:
    """
    Controls the Autonomous AI Pivot Loop:
    Reads Case DB -> Asks AI Brain -> Runs Domain/Identity Recon -> Repeats up to max_depth.
    """

    def __init__(self, db: CaseDatabase, config: ConfigManager, console: Console):
        self.db = db
        self.config = config
        self.console = console

        # Initialize all Engine 2 components
        self.ai_brain = AIBrain(config=config)
        self.domain_recon = DomainRecon(db=db, config=config)
        self.identity_recon = IdentityRecon(db=db, config=config)

        # Track scanned targets in lowercase to prevent infinite loops
        self.visited_targets = set()

    def run_single_recon(self, target: str, target_type: str) -> Dict[str, Any]:
        # Route the target to the right OSINT module based on its type
        target_clean = target.strip()
        t_type = target_type.upper()

        if t_type == "DOMAIN":
            return self.domain_recon.analyze_domain(target_clean)
        elif t_type in ("EMAIL", "USERNAME"):
            return self.identity_recon.analyze_identity(target_clean, target_type=t_type)
        else:
            return {"error": f"Unsupported target type: {t_type}"}

    def run_autopivot(self, max_depth: int = 2) -> Dict[str, Any]:
        # Run the autonomous AI-driven investigation loop
        all_executed_pivots: List[Dict[str, Any]] = []
        final_summary = ""

        # Pre-populate visited targets from existing OSINT findings in the DB
        for finding in self.db.get_all_osint_findings():
            self.visited_targets.add(finding["target"].lower())

        for depth in range(1, max_depth + 1):
            self.console.print(f"\n[bold cyan]━━━ AI Pivot Depth {depth}/{max_depth} ━━━[/bold cyan]")

            # 1. Pull latest evidence from SQLite Case DB
            iocs = self.db.get_all_iocs()
            secrets = self.db.get_all_secrets()
            osint_findings = self.db.get_all_osint_findings()

            if not iocs and not secrets and not osint_findings:
                self.console.print("[yellow]No evidence in case DB yet. Run 'analyze' or 'recon' first.[/yellow]")
                break

            # 2. Ask Gemini AI Brain for next pivot recommendations
            with self.console.status("[bold magenta]Gemini AI Brain is analyzing clues...[/bold magenta]", spinner="dots"):
                ai_decision = self.ai_brain.decide_next_pivots(
                    iocs=iocs,
                    secrets=secrets,
                    osint_findings=osint_findings,
                    visited_targets=self.visited_targets,
                )

            final_summary = ai_decision.get("summary", "")
            pivots = ai_decision.get("pivots", [])

            self.console.print(f"[bold white]AI Assessment:[/bold white] {final_summary}")

            if not pivots:
                self.console.print("[green]No new high-value pivots remaining. Stopping loop.[/green]")
                break

            # 3. Execute each AI-recommended pivot
            for pivot in pivots:
                target = str(pivot.get("target", "")).strip()
                t_type = str(pivot.get("target_type", "")).upper()
                reason = str(pivot.get("reason", ""))
                source_clue = str(pivot.get("source_clue", ""))

                if not target or target.lower() in self.visited_targets:
                    continue

                self.visited_targets.add(target.lower())
                self.console.print(f"  [bold yellow]↳ Pivoting to [{t_type}]:[/bold yellow] {target} [dim]({reason})[/dim]")

                # Record the AI decision in SQLite
                self.db.add_ai_pivot(
                    depth_level=depth,
                    source_clue=source_clue,
                    recommended_target=target,
                    target_type=t_type,
                    reason=reason,
                    status="EXECUTED",
                )

                # Execute the appropriate OSINT module
                with self.console.status(f"[green]Running {t_type} recon on {target}...[/green]", spinner="dots"):
                    self.run_single_recon(target, t_type)

                all_executed_pivots.append({
                    "depth": depth,
                    "target": target,
                    "type": t_type,
                    "reason": reason,
                })

        self.db.log_action(
            "AI_AUTOPIVOT_COMPLETE",
            f"Completed up to depth {max_depth}. Executed {len(all_executed_pivots)} AI pivots.",
        )

        return {
            "summary": final_summary,
            "executed_pivots": all_executed_pivots,
        }