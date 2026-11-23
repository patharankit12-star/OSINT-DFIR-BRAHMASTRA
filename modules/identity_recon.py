import re
import shutil
import subprocess
from typing import Any, Dict, List
import requests

from core.config import ConfigManager
from core.database import CaseDatabase


class IdentityRecon:
    """
    Engine 2 (Part B): Performs username and email attribution using
    GitHub API, .patch hidden email/timezone carving, and optional Holehe CLI.
    """

    def __init__(self, db: CaseDatabase, config: ConfigManager):
        # Connect to the active SQLite case database and API config manager
        self.db = db
        self.config = config
        self.headers = {"User-Agent": "OSINT-DFIR-Brahmastra/1.0"}

        # Add GitHub Personal Access Token if available (increases rate limit from 60 to 5000/hr)
        gh_token = self.config.get_api_key("github")
        if gh_token:
            self.headers["Authorization"] = f"token {gh_token}"

    def analyze_github_username(self, username: str) -> Dict[str, Any]:
        # Fetch GitHub profile details, public repos, and carve hidden emails from .patch commits
        results: Dict[str, Any] = {
            "username": username,
            "profile": {},
            "repos": [],
            "carved_emails": [],
            "carved_timezones": [],
        }

        try:
            # 1. Fetch basic user profile
            profile_url = f"https://api.github.com/users/{username}"
            resp = requests.get(profile_url, headers=self.headers, timeout=15)
            if resp.status_code != 200:
                results["error"] = f"GitHub user not found or API limit hit (HTTP {resp.status_code})"
                return results

            data = resp.json()
            profile_fields = ["name", "bio", "location", "company", "blog", "email", "twitter_username"]
            for field in profile_fields:
                val = data.get(field)
                if val:
                    results["profile"][field] = val
                    self.db.add_osint_finding(
                        username, "USERNAME", "github_api", f"PROFILE_{field.upper()}", str(val)
                    )

            # 2. Fetch up to 5 most recently updated public repositories
            repos_url = f"https://api.github.com/users/{username}/repos?sort=updated&per_page=5"
            repos_resp = requests.get(repos_url, headers=self.headers, timeout=15)
            if repos_resp.status_code == 200:
                repos = repos_resp.json()
                carved_emails = set()
                carved_timezones = set()

                for repo in repos:
                    repo_name = repo.get("full_name")
                    if not repo_name or repo.get("fork"):
                        # Skip forked repos to avoid attributing someone else's commits
                        continue

                    results["repos"].append(repo_name)
                    self.db.add_osint_finding(username, "USERNAME", "github_api", "PUBLIC_REPO", repo_name)

                    # 3. Fetch latest commit to perform .patch email & timezone carving
                    commits_url = f"https://api.github.com/repos/{repo_name}/commits?per_page=2"
                    c_resp = requests.get(commits_url, headers=self.headers, timeout=15)
                    if c_resp.status_code == 200:
                        for commit in c_resp.json():
                            html_url = commit.get("html_url")
                            if not html_url:
                                continue

                            # Append .patch to commit URL to get raw Git header with email & timezone
                            patch_resp = requests.get(f"{html_url}.patch", timeout=10)
                            if patch_resp.status_code == 200:
                                patch_text = patch_resp.text[:1500]  # Only need the top header lines

                                # Extract email from "From: Name <email@domain.com>"
                                email_matches = re.findall(r"From:.*<([^>]+)>", patch_text)
                                for em in email_matches:
                                    if "noreply.github.com" not in em.lower():
                                        carved_emails.add(em.strip())

                                # Extract timezone offset from "Date: ... +0530"
                                tz_matches = re.findall(r"Date:.*?([+-]\d{4})", patch_text)
                                for tz in tz_matches:
                                    carved_timezones.add(tz.strip())

                # Save carved emails and timezones to SQLite
                for email in carved_emails:
                    results["carved_emails"].append(email)
                    self.db.add_osint_finding(username, "USERNAME", "github_patch", "HIDDEN_EMAIL", email)

                for tz in carved_timezones:
                    results["carved_timezones"].append(tz)
                    self.db.add_osint_finding(username, "USERNAME", "github_patch", "TIMEZONE", tz)

        except Exception as e:
            results["error"] = f"GitHub recon failed: {str(e)}"

        return results

    def search_github_by_email(self, email: str) -> List[str]:
        # Reverse-search GitHub commits to find usernames linked to an email address
        linked_users = set()
        url = f"https://api.github.com/search/commits?q=author-email:{email}&per_page=5"

        try:
            resp = requests.get(url, headers=self.headers, timeout=15)
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    author = item.get("author")
                    if author and author.get("login"):
                        login = author["login"]
                        linked_users.add(login)
                        self.db.add_osint_finding(email, "EMAIL", "github_search", "LINKED_GITHUB_USER", login)
        except Exception:
            pass

        return list(linked_users)

    def run_holehe(self, email: str) -> List[str]:
        # Optional wrapper: runs 'holehe' CLI if installed on the system (e.g., Kali Linux)
        if not shutil.which("holehe"):
            return []

        registered_sites = []
        try:
            result = subprocess.run(
                ["holehe", "--only-used", "--no-color", email],
                capture_output=True,
                text=True,
                timeout=45,
            )
            # Parse lines starting with [+] which indicate registered platforms
            for line in result.stdout.splitlines():
                if line.strip().startswith("[+]"):
                    site = line.replace("[+]", "").strip()
                    if site:
                        registered_sites.append(site)
                        self.db.add_osint_finding(email, "EMAIL", "holehe", "REGISTERED_SITE", site)
        except Exception:
            pass

        return registered_sites

    def analyze_identity(self, target: str, target_type: str = "USERNAME") -> Dict[str, Any]:
        # Main orchestrator method for Identity Recon
        target = target.strip()
        target_type = target_type.upper()

        if target_type == "EMAIL" or "@" in target:
            linked_gh = self.search_github_by_email(target)
            holehe_sites = self.run_holehe(target)

            self.db.log_action(
                "IDENTITY_RECON_COMPLETE",
                f"Email: {target} | Linked GitHub: {len(linked_gh)} | Holehe sites: {len(holehe_sites)}",
            )
            return {
                "target": target,
                "type": "EMAIL",
                "linked_github_users": linked_gh,
                "holehe_sites": holehe_sites,
            }
        else:
            gh_data = self.analyze_github_username(target)
            self.db.log_action(
                "IDENTITY_RECON_COMPLETE",
                f"Username: {target} | Carved emails: {len(gh_data.get('carved_emails', []))}",
            )
            return {
                "target": target,
                "type": "USERNAME",
                "github": gh_data,
            }