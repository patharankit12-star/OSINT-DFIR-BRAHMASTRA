from typing import Any, Dict, List
from rich.console import Console

from core.ai_brain import AIBrain
from core.config import ConfigManager
from core.database import CaseDatabase
from modules.domain_recon import DomainRecon
from modules.email_osint import EmailOSINT
from modules.phone_osint import PhoneOSINT
from modules.username_osint import UsernameOSINT


class AutoPivotOrchestrator:
    """
    Controls both direct OSINT routing and the Autonomous AI Pivot Loop
    across Domain, Phone, Email, and Username OSINT engines.
    """

    def __init__(self, db: CaseDatabase, config: ConfigManager, console: Console):
        self.db = db
        self.config = config
        self.console = console

        # Initialize AI Brain and all Phase 2 & Phase 3 OSINT modules
        self.ai_brain = AIBrain(config=config)
        self.domain_recon = DomainRecon(db=db, config=config)
        self.phone_osint = PhoneOSINT(db=db)
        self.email_osint = EmailOSINT(db=db, config=config)
        self.username_osint = UsernameOSINT(db=db, config=config)

        self.visited_targets = set()

    def run_single_recon(self, target: str, target_type: str) -> Dict[str, Any]:
        # Route the target to the appropriate Phase 2 or Phase 3 OSINT engine
        target_clean = target.strip()
        t_type = target_type.upper()

        if t_type == "DOMAIN":
            return self.domain_recon.analyze_domain(target_clean)
        elif t_type == "EMAIL":
            return self.email_osint.analyze_email(target_clean)
        elif t_type == "USERNAME":
            return self.username_osint.analyze_username(target_clean)
        elif t_type == "PHONE":
            return self.phone_osint.analyze_phone(target_clean)
        else:
            return {"error": f"Unsupported target type: {t_type}"}

    def run_autopivot(self, max_depth: int = 2) -> Dict[str, Any]:
        all_executed_pivots: List[Dict[str, Any]] = []
        final_summary = ""

        for finding in self.db.get_all_osint_findings():
            self.visited_targets.add(finding["target"].lower())

        for depth in range(1, max_depth + 1):
            self.console.print(f"\n[bold cyan]━━━ AI Pivot Depth {depth}/{max_depth} ━━━[/bold cyan]")

            iocs = self.db.get_all_iocs()
            secrets = self.db.get_all_secrets()
            osint_findings = self.db.get_all_osint_findings()

            if not iocs and not secrets and not osint_findings:
                self.console.print("[yellow]No evidence in case DB yet. Run 'analyze', 'recon', 'phone', 'email', or 'username' first.[/yellow]")
                break

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

            for pivot in pivots:
                target = str(pivot.get("target", "")).strip()
                t_type = str(pivot.get("target_type", "")).upper()
                reason = str(pivot.get("reason", ""))
                source_clue = str(pivot.get("source_clue", ""))

                if not target or target.lower() in self.visited_targets:
                    continue

                self.visited_targets.add(target.lower())
                self.console.print(f"  [bold yellow]↳ Pivoting to [{t_type}]:[/bold yellow] {target} [dim]({reason})[/dim]")

                self.db.add_ai_pivot(
                    depth_level=depth,
                    source_clue=source_clue,
                    recommended_target=target,
                    target_type=t_type,
                    reason=reason,
                    status="EXECUTED",
                )

                with self.console.status(f"[green]Running {t_type} OSINT on {target}...[/green]", spinner="dots"):
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