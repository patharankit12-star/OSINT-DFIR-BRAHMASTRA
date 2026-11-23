from typing import Any, Dict, List
from urllib.parse import urlparse
import dns.resolver
import requests
import whois

from core.config import ConfigManager
from core.database import CaseDatabase


class DomainRecon:
    """
    Engine 2 (Part A): Performs multi-source domain intelligence gathering using
    WHOIS, DNS, crt.sh, VirusTotal API, and Hunter.io API.
    """

    def __init__(self, db: CaseDatabase, config: ConfigManager):
        # Connect to the active SQLite case database and API config manager
        self.db = db
        self.config = config
        self.headers = {"User-Agent": "OSINT-DFIR-Brahmastra/1.0"}

    def clean_domain(self, raw_target: str) -> str:
        # Remove http://, https://, paths, and extra spaces to get a clean domain name
        target = raw_target.strip().lower()
        if target.startswith(("http://", "https://")):
            target = urlparse(target).netloc
        return target.split("/")[0].split(":")[0]

    def run_whois(self, domain: str) -> Dict[str, Any]:
        # Fetch WHOIS registration details (Registrar, Creation Date, Emails)
        results = {}
        try:
            w = whois.whois(domain)
            registrar = w.registrar
            creation_date = w.creation_date
            emails = w.emails

            # Handle cases where python-whois returns a list instead of a single value
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if registrar:
                results["registrar"] = str(registrar)
                self.db.add_osint_finding(domain, "DOMAIN", "whois", "REGISTRAR", str(registrar))

            if creation_date:
                results["creation_date"] = str(creation_date)
                self.db.add_osint_finding(domain, "DOMAIN", "whois", "CREATION_DATE", str(creation_date))

            if emails:
                email_list = emails if isinstance(emails, list) else [emails]
                results["emails"] = email_list
                for email in set(email_list):
                    self.db.add_osint_finding(domain, "DOMAIN", "whois", "EMAIL", str(email))

        except Exception as e:
            results["error"] = f"WHOIS failed: {str(e)}"
        return results

    def run_dns(self, domain: str) -> Dict[str, List[str]]:
        # Query A, MX, NS, and TXT DNS records
        record_types = ["A", "MX", "NS", "TXT"]
        dns_results: Dict[str, List[str]] = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                values = [str(rdata).strip('"') for rdata in answers]
                dns_results[rtype] = values

                for val in values:
                    self.db.add_osint_finding(domain, "DOMAIN", "dns", f"DNS_{rtype}", val)
            except Exception:
                # Skip record types that do not exist for this domain
                continue

        return dns_results

    def run_crtsh(self, domain: str) -> List[str]:
        # Query crt.sh Certificate Transparency logs for free passive subdomains
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            resp = requests.get(url, headers=self.headers, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    # Some certificates contain multiple domains separated by newlines
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower().lstrip("*.")
                        if sub.endswith(domain) and sub != domain:
                            subdomains.add(sub)

                # Save discovered subdomains to the SQLite database (limit top 50 to avoid noise)
                for sub in sorted(subdomains)[:50]:
                    self.db.add_osint_finding(domain, "DOMAIN", "crt.sh", "SUBDOMAIN", sub)
        except Exception:
            pass

        return sorted(subdomains)[:50]

    def run_virustotal(self, domain: str) -> Dict[str, Any]:
        # Check domain reputation and passive subdomains using VirusTotal API v3
        api_key = self.config.get_api_key("virustotal")
        if not api_key:
            return {"skipped": "No VirusTotal API key configured"}

        vt_results: Dict[str, Any] = {}
        vt_headers = {"x-apikey": api_key}

        try:
            # 1. Get main domain reputation and analysis stats
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            resp = requests.get(url, headers=vt_headers, timeout=15)

            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                reputation = attrs.get("reputation", 0)

                vt_results["malicious"] = malicious
                vt_results["suspicious"] = suspicious
                vt_results["reputation"] = reputation

                summary_str = f"Malicious: {malicious} | Suspicious: {suspicious} | Reputation: {reputation}"
                self.db.add_osint_finding(
                    domain, "DOMAIN", "virustotal", "REPUTATION", summary_str, raw_data=stats
                )

            # 2. Fetch up to 20 passive subdomains from VirusTotal
            sub_url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=20"
            sub_resp = requests.get(sub_url, headers=vt_headers, timeout=15)
            if sub_resp.status_code == 200:
                vt_subs = [item.get("id") for item in sub_resp.json().get("data", []) if item.get("id")]
                vt_results["subdomains"] = vt_subs
                for sub in vt_subs:
                    self.db.add_osint_finding(domain, "DOMAIN", "virustotal", "SUBDOMAIN", sub)

        except Exception as e:
            vt_results["error"] = f"VirusTotal API error: {str(e)}"

        return vt_results

    def run_hunter(self, domain: str) -> List[Dict[str, str]]:
        # Search for corporate employee emails using Hunter.io API
        api_key = self.config.get_api_key("hunter_io")
        if not api_key:
            return []

        emails_found = []
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"

        try:
            resp = requests.get(url, headers=self.headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                for person in data.get("emails", []):
                    email = person.get("value")
                    position = person.get("position") or "Unknown Role"
                    if email:
                        emails_found.append({"email": email, "position": position})
                        self.db.add_osint_finding(
                            domain, "DOMAIN", "hunter_io", "EMAIL", f"{email} ({position})", raw_data=person
                        )
        except Exception:
            pass

        return emails_found

    def analyze_domain(self, raw_target: str) -> Dict[str, Any]:
        # Main orchestrator method for Domain Recon
        domain = self.clean_domain(raw_target)

        whois_data = self.run_whois(domain)
        dns_data = self.run_dns(domain)
        crtsh_subs = self.run_crtsh(domain)
        vt_data = self.run_virustotal(domain)
        hunter_emails = self.run_hunter(domain)

        # Log completion in Chain of Custody
        self.db.log_action(
            "DOMAIN_RECON_COMPLETE",
            f"Target: {domain} | crt.sh subs: {len(crtsh_subs)} | Hunter emails: {len(hunter_emails)}",
        )

        return {
            "domain": domain,
            "whois": whois_data,
            "dns": dns_data,
            "crtsh_subdomains": crtsh_subs,
            "virustotal": vt_data,
            "hunter_emails": hunter_emails,
        }