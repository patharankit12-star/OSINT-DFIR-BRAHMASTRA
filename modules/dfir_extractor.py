import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any

from core.database import CaseDatabase


class DFIRExtractor:
    """
    Engine 1: Extracts cryptographic hashes, ExifTool metadata, Gitleaks secrets,
    and regex-based IOCs/C2 artifacts from any suspicious file.
    """

    # Regex patterns for extracting high-value forensic IOCs and secrets
    IOC_PATTERNS = {
        "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "URL": r"https?://[^\s\"'<>()]+",
        "IPV4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "WIN_PATH": r"[A-Za-z]:\\Users\\[a-zA-Z0-9._-]+(?:\\[^\s\"'<>|]+)*",
        "LINUX_PATH": r"/home/[a-zA-Z0-9._-]+(?:/[^\s\"'<>|]+)*",
        "BTC_WALLET": r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
        "ETH_WALLET": r"\b0x[a-fA-F0-9]{40}\b",
    }

    SECRET_PATTERNS = {
        "TELEGRAM_BOT_TOKEN": r"\b\d{8,10}:[a-zA-Z0-9_-]{35}\b",
        "DISCORD_WEBHOOK": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+",
        "AWS_ACCESS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
    }

    def __init__(self, db: CaseDatabase):
        # Connect this extractor to the active SQLite case database
        self.db = db

    def calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        # Calculate MD5 and SHA-256 hashes in 64KB chunks (memory-safe for large files)
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

        return {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
        }

    def extract_exif_metadata(self, file_path: Path) -> Dict[str, Any]:
        # Check if exiftool is installed in the system PATH
        if not shutil.which("exiftool"):
            return {"_warning": "exiftool not installed on this system"}

        try:
            # Run exiftool with -j flag to get clean JSON output
            result = subprocess.run(
                ["exiftool", "-j", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, list) and len(data) > 0:
                    return data[0]
        except Exception as e:
            return {"_error": f"ExifTool failed: {str(e)}"}

        return {}

    def run_gitleaks(self, file_path: Path) -> list:
        # Check if gitleaks is installed in the system PATH
        if not shutil.which("gitleaks"):
            return []

        leaks_found = []
        # Create a temporary JSON file to store gitleaks output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        try:
            # Run gitleaks in --no-git mode for single file scanning
            # Note: Gitleaks returns exit code 1 when leaks are found, so we do not raise on non-zero
            subprocess.run(
                [
                    "gitleaks",
                    "detect",
                    "--no-git",
                    "--source",
                    str(file_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    report_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            # Read and parse the JSON report if gitleaks wrote any findings
            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                    findings = json.load(f)
                    for item in findings:
                        leaks_found.append({
                            "type": item.get("RuleID", "GITLEAKS_SECRET"),
                            "value": item.get("Secret", item.get("Match", "")),
                        })
        except Exception:
            pass
        finally:
            # Always delete the temporary report file
            if os.path.exists(report_path):
                os.remove(report_path)

        return leaks_found

    def extract_regex_artifacts(self, file_path: Path) -> Dict[str, list]:
        # Read raw file bytes and decode safely to scan for embedded strings/IOCs
        with open(file_path, "rb") as f:
            raw_text = f.read().decode("utf-8", errors="ignore")

        found_iocs = []
        found_secrets = []

        # Scan for IOCs (Emails, URLs, IPs, Paths, Wallets)
        for ioc_type, pattern in self.IOC_PATTERNS.items():
            matches = set(re.findall(pattern, raw_text))
            for match in matches:
                found_iocs.append({"type": ioc_type, "value": match})

        # Scan for custom C2/Attacker secrets (Telegram bots, Discord webhooks, AWS keys)
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = set(re.findall(pattern, raw_text))
            for match in matches:
                found_secrets.append({"type": secret_type, "value": match})

        return {"iocs": found_iocs, "secrets": found_secrets}

    def analyze_file(self, target_file: str) -> Dict[str, Any]:
        # Main orchestrator method for Engine 1
        file_path = Path(target_file).resolve()
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"Target file not found: {file_path}")

        # 1. File stats and cryptographic hashes
        file_size = file_path.stat().st_size
        hashes = self.calculate_hashes(file_path)

        # 2. Register artifact in SQLite database
        artifact_id = self.db.add_artifact(
            file_name=file_path.name,
            file_path=str(file_path),
            file_size=file_size,
            md5=hashes["md5"],
            sha256=hashes["sha256"],
        )

        # 3. Extract and save ExifTool metadata
        metadata = self.extract_exif_metadata(file_path)
        if metadata:
            self.db.add_metadata(artifact_id, metadata)

        # 4. Extract and save Regex IOCs & Custom Secrets
        regex_results = self.extract_regex_artifacts(file_path)
        for ioc in regex_results["iocs"]:
            self.db.add_ioc(artifact_id, ioc["type"], ioc["value"], source="regex_carver")

        for secret in regex_results["secrets"]:
            self.db.add_secret(artifact_id, secret["type"], secret["value"], source="regex_carver")

        # 5. Run Gitleaks and save any discovered secrets
        gitleaks_results = self.run_gitleaks(file_path)
        for leak in gitleaks_results:
            self.db.add_secret(artifact_id, leak["type"], leak["value"], source="gitleaks")

        # Log completion in Chain of Custody
        self.db.log_action(
            "DFIR_EXTRACTION_COMPLETE",
            f"Artifact ID {artifact_id}: {len(metadata)} metadata tags, "
            f"{len(regex_results['iocs'])} IOCs, "
            f"{len(regex_results['secrets']) + len(gitleaks_results)} secrets.",
        )

        # Return clean summary dictionary for CLI display
        return {
            "artifact_id": artifact_id,
            "file_name": file_path.name,
            "file_size": file_size,
            "hashes": hashes,
            "metadata_count": len(metadata),
            "metadata": metadata,
            "iocs": regex_results["iocs"],
            "secrets": regex_results["secrets"] + gitleaks_results,
        }