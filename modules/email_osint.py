import hashlib
import shutil
import subprocess
from typing import Any, Dict, List
import dns.resolver
import requests

from core.config import ConfigManager
from core.database import CaseDatabase


class EmailOSINT:
    """
    Engine 3 (Part B): Deep Email Intelligence using MX/Disposable check,
    XposedOrNot (free breach API), Gravatar profile recon, GitHub search, and Holehe CLI.
    """

    # Common disposable/temporary email providers used by scammers
    DISPOSABLE_DOMAINS = {
        "tempmail.com", "temp-mail.org", "guerrillamail.com", "10minutemail.com",
        "yopmail.com", "mailinator.com", "sharklasers.com", "throwawaymail.com",
        "getnada.com", "dispostable.com", "trashmail.com", "mohmal.com",
    }

    def __init__(self, db: CaseDatabase, config: ConfigManager):
        self.db = db
        self.config = config
        self.headers = {"User-Agent": "OSINT-DFIR-Brahmastra/1.0"}

        # Use GitHub token if configured for higher API rate limits
        gh_token = self.config.get_api_key("github")
        self.gh_headers = dict(self.headers)
        if gh_token:
            self.gh_headers["Authorization"] = f"token {gh_token}"

    def check_email_hygiene(self, email: str) -> Dict[str, Any]:
        # Check if the email domain is disposable and verify its MX (mail) records
        results: Dict[str, Any] = {"disposable": False, "mx_records": []}
        try:
            domain = email.split("@")[1].lower().strip()
        except IndexError:
            self.db.add_osint_finding(email, "EMAIL", "email_hygiene", "STATUS", "Invalid email format")
            return results

        # 1. Disposable / Burner Email Check
        is_disposable = domain in self.DISPOSABLE_DOMAINS
        results["disposable"] = is_disposable
        disposable_label = "YES (Burner/Temp Email)" if is_disposable else "NO (Standard Domain)"
        self.db.add_osint_finding(email, "EMAIL", "email_hygiene", "DISPOSABLE_CHECK", disposable_label)

        # 2. DNS MX Record Check (confirms domain can receive emails & reveals mail provider)
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 15
            answers = resolver.resolve(domain, "MX")
            mx_list = [str(rdata.exchange).rstrip(".") for rdata in answers]
            results["mx_records"] = mx_list
            for mx in mx_list[:5]:
                self.db.add_osint_finding(email, "EMAIL", "email_hygiene", "MX_SERVER", mx)
        except Exception:
            self.db.add_osint_finding(email, "EMAIL", "email_hygiene", "MX_SERVER", "No MX records found (Invalid/Dead domain)")

        return results

    def check_xposedornot(self, email: str) -> List[str]:
        # Query XposedOrNot free public API to check for known data breaches
        breaches_found = []
        url = f"https://api.xposedornot.com/v1/check-email/{email}"

        try:
            resp = requests.get(url, headers=self.headers, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                # API returns {"breaches": [["Breach1", "Breach2", ...]]}
                raw_breaches = data.get("breaches", [])
                if raw_breaches and isinstance(raw_breaches[0], list):
                    breaches_found = raw_breaches[0]
                elif isinstance(raw_breaches, list):
                    breaches_found = raw_breaches

                if breaches_found:
                    for b in breaches_found[:30]:
                        self.db.add_osint_finding(email, "EMAIL", "xposedornot", "DATA_BREACH", str(b))
                else:
                    self.db.add_osint_finding(email, "EMAIL", "xposedornot", "STATUS", "No public breaches found")
            elif resp.status_code == 404:
                self.db.add_osint_finding(email, "EMAIL", "xposedornot", "STATUS", "Clean (0 breaches found)")
            else:
                self.db.add_osint_finding(email, "EMAIL", "xposedornot", "STATUS", f"API Error (HTTP {resp.status_code})")
        except Exception as e:
            self.db.add_osint_finding(email, "EMAIL", "xposedornot", "STATUS", f"Skipped ({type(e).__name__})")

        return breaches_found

    def check_gravatar(self, email: str) -> Dict[str, Any]:
        # Hash email with MD5 to check if a public Gravatar profile exists
        gravatar_data: Dict[str, Any] = {}
        email_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
        url = f"https://en.gravatar.com/{email_hash}.json"

        try:
            resp = requests.get(url, headers=self.headers, timeout=15)
            if resp.status_code == 200:
                entries = resp.json().get("entry", [])
                if entries:
                    profile = entries[0]
                    fields = {
                        "DISPLAY_NAME": profile.get("displayName"),
                        "USERNAME": profile.get("preferredUsername"),
                        "LOCATION": profile.get("currentLocation"),
                        "ABOUT": profile.get("aboutMe"),
                        "AVATAR_URL": profile.get("thumbnailUrl"),
                        "PROFILE_URL": profile.get("profileUrl"),
                    }
                    for key, val in fields.items():
                        if val:
                            gravatar_data[key] = str(val)
                            self.db.add_osint_finding(email, "EMAIL", "gravatar", key, str(val))
            elif resp.status_code == 404:
                self.db.add_osint_finding(email, "EMAIL", "gravatar", "STATUS", "No Gravatar profile found")
        except Exception:
            pass

        return gravatar_data

    def check_github_email(self, email: str) -> List[str]:
        # Reverse-search GitHub commits to find usernames linked to this email
        linked_users = set()
        url = f"https://api.github.com/search/commits?q=author-email:{email}&per_page=5"

        try:
            resp = requests.get(url, headers=self.gh_headers, timeout=20)
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
        # Optional CLI wrapper: runs 'holehe' if installed (checks 100+ sites for registration)
        if not shutil.which("holehe"):
            self.db.add_osint_finding(email, "EMAIL", "holehe", "STATUS", "Skipped (holehe not installed)")
            return []

        registered_sites = []
        try:
            result = subprocess.run(
                ["holehe", "--only-used", "--no-color", email],
                capture_output=True,
                text=True,
                timeout=60,
            )
            for line in result.stdout.splitlines():
                if line.strip().startswith("[+]"):
                    site = line.replace("[+]", "").strip()
                    if site:
                        registered_sites.append(site)
                        self.db.add_osint_finding(email, "EMAIL", "holehe", "REGISTERED_SITE", site)

            if not registered_sites:
                self.db.add_osint_finding(email, "EMAIL", "holehe", "STATUS", "0 registered sites detected")
        except Exception as e:
            self.db.add_osint_finding(email, "EMAIL", "holehe", "STATUS", f"Skipped ({type(e).__name__})")

        return registered_sites

    def analyze_email(self, raw_email: str) -> Dict[str, Any]:
        # Main orchestrator method for Email OSINT
        email = raw_email.strip().lower()

        hygiene = self.check_email_hygiene(email)
        breaches = self.check_xposedornot(email)
        gravatar = self.check_gravatar(email)
        github_users = self.check_github_email(email)
        holehe_sites = self.run_holehe(email)

        self.db.log_action(
            "EMAIL_OSINT_COMPLETE",
            f"Target: {email} | Breaches: {len(breaches)} | GitHub: {len(github_users)} | Holehe: {len(holehe_sites)}",
        )

        return {
            "email": email,
            "hygiene": hygiene,
            "breaches": breaches,
            "gravatar": gravatar,
            "github_users": github_users,
            "holehe_sites": holehe_sites,
        }