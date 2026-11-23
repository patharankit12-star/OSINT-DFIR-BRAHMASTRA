import socket
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
    WHOIS (detailed), DNS, crt.sh, VirusTotal API, and Hunter.io API with high timeouts.
    """

    def __init__(self, db: CaseDatabase, config: ConfigManager):
        self.db = db
        self.config = config
        self.headers = {"User-Agent": "OSINT-DFIR-Brahmastra/1.0"}

    def clean_domain(self, raw_target: str) -> str:
        # Remove http://, https://, paths, and ports to get a clean domain name
        target = raw_target.strip().lower()
        if target.startswith(("http://", "https://")):
            target = urlparse(target).netloc
        return target.split("/")[0].split(":")[0]

    def _first_val(self, val: Any) -> str:
        # Helper to safely extract a single clean string if python-whois returns a list
        if isinstance(val, list) and len(val) > 0:
            return str(val[0])
        return str(val) if val else ""

    def run_whois(self, domain: str) -> Dict[str, Any]:
        # Fetch rich WHOIS details + primary IP address
        results = {}
        try:
            # 1. Resolve primary IPv4 address for quick reference
            try:
                ip_addr = socket.gethostbyname(domain)
                results["ip"] = ip_addr
                self.db.add_osint_finding(domain, "DOMAIN", "whois", "IP_ADDRESS", ip_addr)
            except Exception:
                pass

            # 2. Query WHOIS server
            w = whois.whois(domain)

            fields_map = {
                "DOMAIN_NAME": self._first_val(w.domain_name),
                "REGISTRAR": self._first_val(w.registrar),
                "CREATION_DATE": self._first_val(w.creation_date),
                "EXPIRATION_DATE": self._first_val(w.expiration_date),
                "UPDATED_DATE": self._first_val(w.updated_date),
                "ORGANIZATION": self._first_val(w.org),
                "STATE": self._first_val(w.state),
                "COUNTRY": self._first_val(w.country),
            }

            for tag, value in fields_map.items():
                if value and value.lower() != "none":
                    results[tag.lower()] = value
                    self.db.add_osint_finding(domain, "DOMAIN", "whois", tag, value)

            # Save any public WHOIS emails
            if w.emails:
                email_list = w.emails if isinstance(w.emails, list) else [w.emails]
                results["emails"] = email_list
                for email in set(email_list):
                    if email:
                        self.db.add_osint_finding(domain, "DOMAIN", "whois", "EMAIL", str(email))

        except Exception as e:
            results["error"] = f"WHOIS skipped: {str(e)}"
        return results

    def run_dns(self, domain: str) -> Dict[str, List[str]]:
        # Query A, MX, NS, and TXT DNS records with increased timeout (20s)
        record_types = ["A", "MX", "NS", "TXT"]
        dns_results: Dict[str, List[str]] = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 15
        resolver.lifetime = 20

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                values = [str(rdata).strip('"') for rdata in answers]
                dns_results[rtype] = values

                for val in values:
                    self.db.add_osint_finding(domain, "DOMAIN", "dns", f"DNS_{rtype}", val)
            except Exception:
                # Skip missing record types gracefully
                continue

        return dns_results

    def run_crtsh(self, domain: str) -> List[str]:
        # Query crt.sh with higher timeout (45s) because crt.sh can be slow
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            resp = requests.get(url, headers=self.headers, timeout=45)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower().lstrip("*.")
                        if sub.endswith(domain) and sub != domain:
                            subdomains.add(sub)

                # Save top 30 unique subdomains to keep DB and output clean
                for sub in sorted(subdomains)[:30]:
                    self.db.add_osint_finding(domain, "DOMAIN", "crt.sh", "SUBDOMAIN", sub)
        except Exception:
            # Skip gracefully if crt.sh times out or returns 502/503
            pass

        return sorted(subdomains)[:30]

    def run_virustotal(self, domain: str) -> Dict[str, Any]:
        # Check VirusTotal API v3 with increased timeout (30s)
        api_key = self.config.get_api_key("virustotal")
        if not api_key:
            return {"skipped": "No VirusTotal API key configured"}

        vt_results: Dict[str, Any] = {}
        vt_headers = {"x-apikey": api_key}

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            resp = requests.get(url, headers=vt_headers, timeout=30)

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

            # Fetch passive subdomains from VirusTotal
            sub_url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=15"
            sub_resp = requests.get(sub_url, headers=vt_headers, timeout=30)
            if sub_resp.status_code == 200:
                vt_subs = [item.get("id") for item in sub_resp.json().get("data", []) if item.get("id")]
                vt_results["subdomains"] = vt_subs
                for sub in vt_subs:
                    self.db.add_osint_finding(domain, "DOMAIN", "virustotal", "SUBDOMAIN", sub)

        except Exception as e:
            vt_results["error"] = f"VirusTotal skipped: {str(e)}"

        return vt_results

    def run_hunter(self, domain: str) -> List[Dict[str, str]]:
        # Search for corporate emails using Hunter.io API with increased timeout (30s)
        api_key = self.config.get_api_key("hunter_io")
        if not api_key:
            return []

        emails_found = []
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"

        try:
            resp = requests.get(url, headers=self.headers, timeout=30)
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
        # Run all 5 sources sequentially; each skips gracefully on error
        domain = self.clean_domain(raw_target)

        whois_data = self.run_whois(domain)
        dns_data = self.run_dns(domain)
        crtsh_subs = self.run_crtsh(domain)
        vt_data = self.run_virustotal(domain)
        hunter_emails = self.run_hunter(domain)

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