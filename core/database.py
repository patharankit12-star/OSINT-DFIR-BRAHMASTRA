import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class CaseDatabase:
    """
    Manages an isolated SQLite database for each DFIR/OSINT investigation case.
    Supports Phase 1 (DFIR Artifacts) and Phase 2 (OSINT Findings & AI Pivots).
    """

    def __init__(self, case_name: str, base_dir: str = "cases"):
        # Create the 'cases' directory if it does not exist
        self.case_dir = Path(base_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)

        # Define the path for this specific case's database file
        self.db_path = self.case_dir / f"{case_name}.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Allows accessing columns by name
        self.cursor = self.conn.cursor()

        # Initialize all required forensic and OSINT tables
        self._create_tables()

    def _get_utc_now(self) -> str:
        # Return current UTC timestamp in ISO format for forensic accuracy
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _create_tables(self):
        # 1. Artifacts table: stores basic file info and cryptographic hashes
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                md5_hash TEXT,
                sha256_hash TEXT UNIQUE,
                analyzed_at TEXT
            )
        """)

        # 2. Metadata table: stores key-value pairs extracted by ExifTool
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id INTEGER,
                tag_name TEXT,
                tag_value TEXT,
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
            )
        """)

        # 3. IOCs table: stores Domains, IPs, Emails, URLs, and Local Paths
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id INTEGER,
                ioc_type TEXT,
                ioc_value TEXT,
                source TEXT,
                UNIQUE(artifact_id, ioc_type, ioc_value),
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
            )
        """)

        # 4. Secrets table: stores leaked API keys, Telegram bots, Webhooks, etc.
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id INTEGER,
                secret_type TEXT,
                secret_value TEXT,
                source TEXT,
                UNIQUE(artifact_id, secret_type, secret_value),
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
            )
        """)

        # 5. Audit Log table: tracks every action for Chain of Custody
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                details TEXT
            )
        """)

        # 6. OSINT Findings table (Phase 2): stores WHOIS, DNS, crt.sh, VT, Hunter, GitHub results
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS osint_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                finding_value TEXT NOT NULL,
                raw_data TEXT,
                discovered_at TEXT,
                UNIQUE(target, source_tool, finding_type, finding_value)
            )
        """)

        # 7. AI Pivots table (Phase 2): tracks AI Brain decisions and next-step targets
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_pivots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                depth_level INTEGER,
                source_clue TEXT,
                recommended_target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT,
                status TEXT DEFAULT 'PENDING',
                created_at TEXT
            )
        """)
        self.conn.commit()

    # -------------------- PHASE 1 METHODS --------------------

    def log_action(self, action: str, details: str):
        # Record an action in the Chain of Custody log
        self.cursor.execute(
            "INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
            (self._get_utc_now(), action, details),
        )
        self.conn.commit()

    def add_artifact(self, file_name: str, file_path: str, file_size: int, md5: str, sha256: str) -> int:
        # Check if this exact file (by SHA-256) was already analyzed in this case
        self.cursor.execute("SELECT id FROM artifacts WHERE sha256_hash = ?", (sha256,))
        existing = self.cursor.fetchone()
        if existing:
            return existing["id"]

        # Insert new artifact and return its unique ID
        self.cursor.execute(
            """
            INSERT INTO artifacts (file_name, file_path, file_size, md5_hash, sha256_hash, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (file_name, file_path, file_size, md5, sha256, self._get_utc_now()),
        )
        self.conn.commit()
        artifact_id = self.cursor.lastrowid
        self.log_action("ARTIFACT_ADDED", f"File: {file_name} | SHA256: {sha256}")
        return artifact_id

    def add_metadata(self, artifact_id: int, metadata_dict: dict):
        # Save all ExifTool tags for the given artifact
        rows = [(artifact_id, str(k), str(v)) for k, v in metadata_dict.items()]
        self.cursor.executemany(
            "INSERT INTO metadata (artifact_id, tag_name, tag_value) VALUES (?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def add_ioc(self, artifact_id: int, ioc_type: str, ioc_value: str, source: str):
        # Save unique IOC (INSERT OR IGNORE avoids duplicate entries)
        self.cursor.execute(
            """
            INSERT OR IGNORE INTO iocs (artifact_id, ioc_type, ioc_value, source)
            VALUES (?, ?, ?, ?)
            """,
            (artifact_id, ioc_type, ioc_value, source),
        )
        self.conn.commit()

    def add_secret(self, artifact_id: int, secret_type: str, secret_value: str, source: str):
        # Save unique secret/credential found in the artifact
        self.cursor.execute(
            """
            INSERT OR IGNORE INTO secrets (artifact_id, secret_type, secret_value, source)
            VALUES (?, ?, ?, ?)
            """,
            (artifact_id, secret_type, secret_value, source),
        )
        self.conn.commit()

    # -------------------- PHASE 2 METHODS --------------------

    def add_osint_finding(
        self,
        target: str,
        target_type: str,
        source_tool: str,
        finding_type: str,
        finding_value: str,
        raw_data: Optional[Any] = None,
    ):
        # Convert dict/list raw_data to JSON string if provided
        raw_str = json.dumps(raw_data, default=str) if raw_data is not None else None

        self.cursor.execute(
            """
            INSERT OR IGNORE INTO osint_findings
            (target, target_type, source_tool, finding_type, finding_value, raw_data, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (target, target_type, source_tool, finding_type, str(finding_value), raw_str, self._get_utc_now()),
        )
        self.conn.commit()

    def add_ai_pivot(
        self,
        depth_level: int,
        source_clue: str,
        recommended_target: str,
        target_type: str,
        reason: str,
        status: str = "EXECUTED",
    ):
        # Save AI Brain's pivot recommendation and reasoning
        self.cursor.execute(
            """
            INSERT INTO ai_pivots
            (depth_level, source_clue, recommended_target, target_type, reason, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (depth_level, source_clue, recommended_target, target_type, reason, status, self._get_utc_now()),
        )
        self.conn.commit()

    def get_all_iocs(self) -> List[Dict[str, str]]:
        # Return all IOCs collected in this case
        self.cursor.execute("SELECT ioc_type, ioc_value, source FROM iocs")
        return [dict(row) for row in self.cursor.fetchall()]

    def get_all_secrets(self) -> List[Dict[str, str]]:
        # Return all secrets collected in this case
        self.cursor.execute("SELECT secret_type, secret_value, source FROM secrets")
        return [dict(row) for row in self.cursor.fetchall()]

    def get_all_osint_findings(self) -> List[Dict[str, str]]:
        # Return all OSINT findings collected in this case
        self.cursor.execute(
            "SELECT target, target_type, source_tool, finding_type, finding_value FROM osint_findings"
        )
        return [dict(row) for row in self.cursor.fetchall()]

    def close(self):
        # Safely close the database connection
        self.conn.close()