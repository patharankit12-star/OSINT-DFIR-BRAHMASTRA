import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List
import requests

from core.config import ConfigManager
from core.database import CaseDatabase


class UsernameOSINT:
    """
    Engine 3 (Part C): Fast multi-threaded username scanner across top platforms,
    GitHub profile + .patch hidden email/timezone carving, and optional Sherlock CLI.
    """

    # Top high-value OSINT & tech platforms (URL template -> string that must NOT appear if profile exists)
    PLATFORMS = {
        "GitHub": "https://github.com/{}",
        "Reddit": "https://www.reddit.com/user/{}/about.json",
        "Medium": "https://medium.com/@{}",
        "Linktree": "https://linktr.ee/{}",
        "TryHackMe": "https://tryhackme.com/p/{}",
        "Dev.to": "https://dev.to/{}",
        "Hashnode": "https://hashnode.com/@{}",
        "HackerNews": "https://news.ycombinator.com/user?id={}",
        "Keybase": "https://keybase.io/{}",
        "Pastebin": "https://pastebin.com/u/{}",
        "Replit": "https://replit.com/@{}",
        "Kaggle": "https://www.kaggle.com/{}",
        "DockerHub": "https://hub.docker.com/u/{}",
        "PyPI": "https://pypi.org/user/{}/",
        "GitLab": "https://gitlab.com/{}",
        "Telegram": "https://t.me/{}",
        "Pinterest": "https://www.pinterest.com/{}/",
        "Vimeo": "https://vimeo.com/{}",
    }

    def __init__(self, db: CaseDatabase, config: ConfigManager):
        self.db = db
        self.config = config
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        }

        gh_token = self.config.get_api_key("github")
        self.gh_headers = {"User-Agent": "OSINT-DFIR-Brahmastra/1.0"}
        if gh_token:
            self.gh_headers["Authorization"] = f"token {gh_token}"

    def _check_single_platform(self, platform: str, url_template: str, username: str) -> Dict[str, str]:
        # Check if a username exists on a single platform
        url = url_template.format(username)
        try:
            resp = requests.get(url, headers=self.headers, timeout=10, allow_redirects=True)
            if resp.status_code == 200:
                text_lower = resp.text.lower()
                # Filter out soft-404 pages (platforms that return 200 even when user doesn't exist)
                if platform == "Telegram" and 'tgme_page_extra' not in resp.text and 'tgme_page_title' not in resp.text:
                    return {}
                if platform == "HackerNews" and "no such user" in text_lower:
                    return {}
                if platform == "GitLab" and "sign in" in text_lower and username.lower() not in text_lower:
                    return {}
                if platform == "Reddit" and '"error": 404' in text_lower:
                    return {}

                display_url = url.replace("/about.json", "")
                return {"platform": platform, "url": display_url}
        except Exception:
            pass
        return {}

    def scan_platforms(self, username: str) -> List[Dict[str, str]]:
        # Scan all platforms concurrently using ThreadPoolExecutor (takes ~3-5 seconds total)
        found_profiles = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._check_single_platform, name, tpl, username): name
                for name, tpl in self.PLATFORMS.items()
            }
            for future in as_completed(futures):
                res = future.result()
                if res:
                    found_profiles.append(res)
                    self.db.add_osint_finding(
                        username, "USERNAME", "username_scan", res["platform"].upper(), res["url"]
                    )

        if not found_profiles:
            self.db.add_osint_finding(username, "USERNAME", "username_scan", "STATUS", "No public profiles found")

        return found_profiles

    def analyze_github_deep(self, username: str) -> Dict[str, Any]:
        # Deep GitHub profile + .patch hidden email & timezone carving
        results: Dict[str, Any] = {"profile": {}, "repos": [], "carved_emails": [], "carved_timezones": []}

        try:
            resp = requests.get(f"https://api.github.com/users/{username}", headers=self.gh_headers, timeout=15)
            if resp.status_code != 200:
                return results

            data = resp.json()
            for field in ["name", "bio", "location", "company", "blog", "email", "twitter_username"]:
                val = data.get(field)
                if val:
                    results["profile"][field] = val
                    self.db.add_osint_finding(
                        username, "USERNAME", "github_api", f"PROFILE_{field.upper()}", str(val)
                    )

            # Check latest 5 public repos for .patch commit email/timezone leaks
            repos_resp = requests.get(
                f"https://api.github.com/users/{username}/repos?sort=updated&per_page=5",
                headers=self.gh_headers,
                timeout=15,
            )
            if repos_resp.status_code == 200:
                carved_emails, carved_tz = set(), set()
                for repo in repos_resp.json():
                    repo_name = repo.get("full_name")
                    if not repo_name or repo.get("fork"):
                        continue
                    results["repos"].append(repo_name)
                    self.db.add_osint_finding(username, "USERNAME", "github_api", "PUBLIC_REPO", repo_name)

                    c_resp = requests.get(
                        f"https://api.github.com/repos/{repo_name}/commits?per_page=2",
                        headers=self.gh_headers,
                        timeout=15,
                    )
                    if c_resp.status_code == 200:
                        for commit in c_resp.json():
                            html_url = commit.get("html_url")
                            if not html_url:
                                continue
                            patch_resp = requests.get(f"{html_url}.patch", timeout=10)
                            if patch_resp.status_code == 200:
                                header_chunk = patch_resp.text[:1500]
                                for em in re.findall(r"From:.*<([^>]+)>", header_chunk):
                                    if "noreply.github.com" not in em.lower():
                                        carved_emails.add(em.strip())
                                for tz in re.findall(r"Date:.*?([+-]\d{4})", header_chunk):
                                    carved_tz.add(tz.strip())

                for em in carved_emails:
                    results["carved_emails"].append(em)
                    self.db.add_osint_finding(username, "USERNAME", "github_patch", "HIDDEN_EMAIL", em)
                for tz in carved_tz:
                    results["carved_timezones"].append(tz)
                    self.db.add_osint_finding(username, "USERNAME", "github_patch", "TIMEZONE", tz)
        except Exception:
            pass

        return results

    def run_sherlock(self, username: str) -> List[str]:
        # Optional CLI wrapper: runs 'sherlock' if installed on Kali Linux
        if not shutil.which("sherlock"):
            return []

        found_urls = []
        try:
            res = subprocess.run(
                ["sherlock", username, "--timeout", "10", "--print-found", "--no-color"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            for line in res.stdout.splitlines():
                if line.strip().startswith("[+]"):
                    # Example: [+] Instagram: https://www.instagram.com/user
                    parts = line.replace("[+]", "").strip().split(": ", 1)
                    if len(parts) == 2:
                        site, url = parts[0].strip(), parts[1].strip()
                        found_urls.append(url)
                        self.db.add_osint_finding(username, "USERNAME", "sherlock", site.upper(), url)
        except Exception:
            pass

        return found_urls

    def analyze_username(self, raw_username: str) -> Dict[str, Any]:
        # Main orchestrator method for Username OSINT
        username = raw_username.strip().lstrip("@")

        platforms = self.scan_platforms(username)
        github_deep = self.analyze_github_deep(username)
        sherlock_urls = self.run_sherlock(username)

        self.db.log_action(
            "USERNAME_OSINT_COMPLETE",
            f"Target: {username} | Profiles: {len(platforms)} | Carved Emails: {len(github_deep['carved_emails'])}",
        )

        return {
            "username": username,
            "platforms": platforms,
            "github": github_deep,
            "sherlock": sherlock_urls,
        }