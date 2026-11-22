import sqlite3
from pathlib import Path
from datetime import datetime, timezone


class CaseDatabase:
    """
    Manages an isolated SQLite database for each DFIR/OSINT investigation case.
    """

    def __init__(self, case_name: str, base_dir: str = "cases"):
        # Create the 'cases' directory if it does not exist
        self.case_dir = Path(base_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)

        # Define the path for this specific case's database file
        self.db_path = self.case_dir / f"{case_name}.db"
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()

        # Initialize all required forensic tables
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
        self.conn.commit()

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
            return existing[0]

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

    def close(self):
        # Safely close the database connection
        self.conn.close()