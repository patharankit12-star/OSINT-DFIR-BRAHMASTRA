from pathlib import Path
from typing import Dict, Any
import networkx as nx
from pyvis.network import Network

from core.database import CaseDatabase


class GraphBuilder:
    """
    Phase 4 (Part A): Builds an interactive Mini-Maltego style HTML link-analysis graph
    directly from the SQLite Case Database using NetworkX and PyVis.
    """

    # Color palette for different forensic & OSINT entity types
    COLORS = {
        "CASE": "#00d4ff",       # Cyan
        "ARTIFACT": "#ff4b4b",   # Red
        "SECRET": "#ff8c00",     # Orange
        "DOMAIN": "#3b82f6",     # Blue
        "EMAIL": "#facc15",      # Yellow
        "USERNAME": "#a855f7",   # Purple
        "PHONE": "#22c55e",      # Green
        "BREACH": "#ef4444",     # Crimson
        "INFO": "#94a3b8",       # Slate Gray
    }

    def __init__(self, db: CaseDatabase, case_name: str):
        self.db = db
        self.case_name = case_name
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)

    def _add_node(self, G: nx.DiGraph, node_id: str, label: str, group: str, title: str, size: int = 20):
        # Safely add a styled node without overwriting a more important existing node
        if not node_id:
            return
        if node_id not in G:
            G.add_node(
                node_id,
                label=label[:35] + ("..." if len(label) > 35 else ""),
                color=self.COLORS.get(group, self.COLORS["INFO"]),
                title=title,
                size=size,
                shape="dot",
            )

    def build_graph(self) -> Dict[str, Any]:
        """
        Reads all case tables from SQLite, constructs the relationship graph,
        and exports a standalone dark-mode interactive HTML file.
        """
        G = nx.DiGraph()
        cur = self.db.conn.cursor()

        # 1. Central Case Root Node
        case_node = f"CASE::{self.case_name}"
        self._add_node(
            G,
            case_node,
            label=f"CASE: {self.case_name}",
            group="CASE",
            title=f"Investigation Case: {self.case_name}",
            size=32,
        )

        # 2. Artifacts (Suspicious Files from Phase 1)
        try:
            cur.execute("SELECT file_name, sha256, md5 FROM artifacts")
            for file_name, sha256, md5 in cur.fetchall():
                art_node = f"ARTIFACT::{file_name}"
                self._add_node(
                    G,
                    art_node,
                    label=file_name,
                    group="ARTIFACT",
                    title=f"File: {file_name}\nMD5: {md5}\nSHA-256: {sha256}",
                    size=26,
                )
                G.add_edge(case_node, art_node, label="EVIDENCE", color="#ff4b4b")
        except Exception:
            pass

        # 3. Leaked Secrets & C2 Credentials
        try:
            cur.execute("SELECT secret_type, secret_value FROM secrets")
            for s_type, s_val in cur.fetchall():
                short_val = s_val[:22] + "..." if len(s_val) > 22 else s_val
                sec_node = f"SECRET::{s_type}:{short_val}"
                self._add_node(
                    G,
                    sec_node,
                    label=f"{s_type}",
                    group="SECRET",
                    title=f"Secret Type: {s_type}\nValue: {s_val}",
                    size=22,
                )
                G.add_edge(case_node, sec_node, label="LEAKED_SECRET", color="#ff8c00")
        except Exception:
            pass

        # 4. OSINT Findings (Phase 2 & Phase 3)
        # Skip noisy status messages and long dork URLs to keep the graph clean
        skip_types = {"STATUS", "DORK_GENERAL", "DORK_SOCIAL", "DORK_LEAKS_DOCS"}
        sub_counter: Dict[str, int] = {}

        try:
            cur.execute("SELECT target, target_type, source_tool, finding_type, finding_value FROM osint_findings")
            for target, t_type, source_tool, f_type, f_val in cur.fetchall():
                if not target or not f_val or f_type in skip_types:
                    continue

                t_type_upper = (t_type or "INFO").upper()
                target_node = f"{t_type_upper}::{target.lower()}"

                # Add primary target node (Domain / Email / Username / Phone)
                self._add_node(
                    G,
                    target_node,
                    label=target,
                    group=t_type_upper if t_type_upper in self.COLORS else "INFO",
                    title=f"Target ({t_type_upper}): {target}",
                    size=25,
                )
                if not G.has_edge(case_node, target_node):
                    G.add_edge(case_node, target_node, label=t_type_upper, color="#64748b")

                # Limit subdomains per domain to 10 so the graph doesn't explode
                if f_type == "SUBDOMAIN":
                    sub_counter[target] = sub_counter.get(target, 0) + 1
                    if sub_counter[target] > 10:
                        continue

                # Determine child node group for smart coloring
                child_group = "INFO"
                if f_type in ("EMAIL", "HIDDEN_EMAIL"):
                    child_group = "EMAIL"
                elif f_type in ("SUBDOMAIN", "DOMAIN_NAME", "MX_SERVER"):
                    child_group = "DOMAIN"
                elif f_type in ("LINKED_GITHUB_USER", "USERNAME", "PUBLIC_REPO"):
                    child_group = "USERNAME"
                elif f_type == "DATA_BREACH":
                    child_group = "BREACH"

                # Clean email value if it has role in parentheses e.g. "ashu@tryhackme.com (Co-founder)"
                clean_val = f_val.split(" (")[0].strip() if child_group == "EMAIL" else f_val.strip()
                child_node = f"{child_group}::{clean_val.lower()}" if child_group != "INFO" else f"INFO::{f_type}:{clean_val}"

                self._add_node(
                    G,
                    child_node,
                    label=clean_val,
                    group=child_group,
                    title=f"Source: {source_tool}\nType: {f_type}\nValue: {f_val}",
                    size=16,
                )
                G.add_edge(target_node, child_node, label=f_type, color="#475569")
        except Exception:
            pass

        # 5. AI Auto-Pivot Connections (Highlighted in Magenta/Pink)
        try:
            cur.execute("SELECT depth_level, source_clue, recommended_target, target_type, reason FROM ai_pivots")
            for depth, clue, rec_target, t_type, reason in cur.fetchall():
                t_type_upper = (t_type or "INFO").upper()
                rec_node = f"{t_type_upper}::{rec_target.lower()}"
                self._add_node(
                    G,
                    rec_node,
                    label=rec_target,
                    group=t_type_upper if t_type_upper in self.COLORS else "INFO",
                    title=f"AI Pivot (Depth {depth})\nTarget: {rec_target}\nReason: {reason}",
                    size=24,
                )
                G.add_edge(
                    case_node,
                    rec_node,
                    label=f"AI_PIVOT_D{depth}",
                    color="#e879f9",
                    dashes=True,
                )
        except Exception:
            pass

        # 6. Render Interactive PyVis HTML Graph
        net = Network(
            height="92vh",
            width="100%",
            bgcolor="#0d1117",
            font_color="#e6edf3",
            directed=True,
        )
        net.from_nx(G)

        # Smooth physics layout so nodes spread out cleanly
        net.set_options("""
        {
          "nodes": {
            "font": { "size": 14, "face": "Segoe UI, Roboto, sans-serif" },
            "borderWidth": 2
          },
          "edges": {
            "font": { "size": 10, "color": "#94a3b8", "strokeWidth": 0 },
            "smooth": { "type": "dynamic" },
            "arrows": { "to": { "enabled": true, "scaleFactor": 0.6 } }
          },
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -65,
              "centralGravity": 0.01,
              "springLength": 140,
              "springConstant": 0.08
            },
            "maxVelocity": 40,
            "solver": "forceAtlas2Based",
            "timestep": 0.35,
            "stabilization": { "iterations": 120 }
          }
        }
        """)

        output_path = self.reports_dir / f"{self.case_name}_graph.html"
        net.save_graph(str(output_path))

        self.db.log_action(
            "GRAPH_GENERATED",
            f"Saved interactive graph to {output_path} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)",
        )

        return {
            "graph_path": str(output_path),
            "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges(),
        }