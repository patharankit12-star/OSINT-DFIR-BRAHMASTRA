import re
import urllib.parse
from typing import Any, Dict, Optional
import phonenumbers
import requests
from phonenumbers import carrier, geocoder, timezone, PhoneNumberType

from core.config import ConfigManager
from core.database import CaseDatabase


class PhoneOSINT:
    """
    Engine 3 (Part A): Smart Phone OSINT supporting Indian & Foreign numbers,
    carrier normalization, VoIP detection, optional live NumVerify API, and Google Dorks.
    """

    LINE_TYPE_MAP = {
        PhoneNumberType.MOBILE: "MOBILE",
        PhoneNumberType.FIXED_LINE: "FIXED_LINE (Landline)",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
        PhoneNumberType.VOIP: "VOIP (Potential Virtual/Burner Number)",
        PhoneNumberType.TOLL_FREE: "TOLL_FREE",
        PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
        PhoneNumberType.SHARED_COST: "SHARED_COST",
        PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
        PhoneNumberType.PAGER: "PAGER",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.VOICEMAIL: "VOICEMAIL",
        PhoneNumberType.UNKNOWN: "UNKNOWN",
    }

    # Normalize legacy Indian telecom names to current brand names
    CARRIER_ALIASES = {
        "reliance jio": "Jio (Reliance Jio)",
        "jio": "Jio (Reliance Jio)",
        "airtel": "Airtel",
        "bharti airtel": "Airtel",
        "vodafone": "Vi (Vodafone Idea)",
        "idea": "Vi (Vodafone Idea)",
        "vodafone idea": "Vi (Vodafone Idea)",
        "bsnl": "BSNL",
        "cellone": "BSNL",
        "mtnl": "MTNL",
    }

    def __init__(self, db: CaseDatabase, config: Optional[ConfigManager] = None):
        self.db = db
        self.config = config or ConfigManager()

    def _normalize_input(self, raw_number: str) -> str:
        # Clean spaces, dashes, brackets; convert leading '00' international prefix to '+'
        cleaned = re.sub(r"[^\d+]", "", raw_number.strip())
        if cleaned.startswith("00"):
            cleaned = "+" + cleaned[2:]
        return cleaned

    def _smart_parse(self, cleaned: str, default_region: str = "IN"):
        """
        Intelligently parses both Indian and Foreign numbers even if '+' is omitted.
        """
        # 1. If it already starts with '+', parse directly as international
        if cleaned.startswith("+"):
            return phonenumbers.parse(cleaned, None)

        # 2. If >10 digits without '+' (e.g., 14155552671 or 919876543210), try with '+' first
        if len(cleaned) > 10:
            try:
                parsed_intl = phonenumbers.parse("+" + cleaned, None)
                if phonenumbers.is_valid_number(parsed_intl):
                    return parsed_intl
            except phonenumbers.NumberParseException:
                pass

        # 3. Fallback to default region (e.g., 10-digit Indian number)
        return phonenumbers.parse(cleaned, default_region)

    def _clean_carrier_name(self, raw_carrier: str, region_code: str) -> str:
        # Normalize known carrier names and explain missing offline data clearly
        if not raw_carrier or not raw_carrier.strip():
            if region_code in ("US", "CA"):
                return "Not in offline DB (US/Canada requires live API)"
            return "Unknown / New Series or Ported (MNP)"

        lower_c = raw_carrier.strip().lower()
        for key, clean_name in self.CARRIER_ALIASES.items():
            if key in lower_c:
                return f"{clean_name} (Original Prefix)"
        return f"{raw_carrier.strip()} (Original Prefix)"

    def _fetch_live_numverify(self, e164_num: str) -> Dict[str, str]:
        # Optional live carrier/location check if 'numverify' API key is set in config.yaml
        api_key = self.config.get_api_key("numverify")
        if not api_key:
            return {}

        live_data = {}
        try:
            digits = e164_num.lstrip("+")
            url = f"http://apilayer.net/api/validate?access_key={api_key}&number={digits}&format=1"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    if data.get("carrier"):
                        live_data["LIVE_CARRIER"] = data["carrier"]
                    if data.get("location"):
                        live_data["LIVE_LOCATION"] = data["location"]
                    if data.get("line_type"):
                        live_data["LIVE_LINE_TYPE"] = str(data["line_type"]).upper()
        except Exception:
            pass
        return live_data

    def _build_dorks(self, e164_num: str, national_num: str) -> Dict[str, str]:
        digits_only = e164_num.lstrip("+")
        clean_national = re.sub(r"\D", "", national_num)

        q_general = f'"{e164_num}" OR "{clean_national}"'
        q_social = f'("{e164_num}" OR "{clean_national}") (site:facebook.com OR site:instagram.com OR site:linkedin.com OR site:twitter.com)'
        q_leaks = f'("{e164_num}" OR "{clean_national}") (site:pastebin.com OR site:github.com OR filetype:pdf OR filetype:xlsx)'

        return {
            "WHATSAPP_LINK": f"https://wa.me/{digits_only}",
            "TELEGRAM_LINK": f"https://t.me/+{digits_only}",
            "DORK_GENERAL": f"https://www.google.com/search?q={urllib.parse.quote(q_general)}",
            "DORK_SOCIAL": f"https://www.google.com/search?q={urllib.parse.quote(q_social)}",
            "DORK_LEAKS_DOCS": f"https://www.google.com/search?q={urllib.parse.quote(q_leaks)}",
        }

    def analyze_phone(self, raw_number: str, default_region: str = "IN") -> Dict[str, Any]:
        cleaned = self._normalize_input(raw_number)
        results: Dict[str, Any] = {"raw_input": raw_number, "valid": False}

        try:
            parsed = self._smart_parse(cleaned, default_region=default_region)
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)

            if not is_valid:
                self.db.add_osint_finding(
                    raw_number, "PHONE", "phone_osint", "STATUS", f"Invalid Number (Possible: {is_possible})"
                )
                results["error"] = "Phone number is not valid."
                return results

            # Standardize formats
            e164_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            intl_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            nat_fmt = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

            # Extract offline geo, carrier, line type, and timezone
            region_code = phonenumbers.region_code_for_number(parsed) or "Unknown"
            location = geocoder.description_for_number(parsed, "en") or region_code
            raw_carrier = carrier.name_for_number(parsed, "en")
            telecom_carrier = self._clean_carrier_name(raw_carrier, region_code)
            num_type_code = phonenumbers.number_type(parsed)
            line_type = self.LINE_TYPE_MAP.get(num_type_code, "UNKNOWN")
            tz_list = list(timezone.time_zones_for_number(parsed))
            tz_str = ", ".join(tz_list) if tz_list else "Unknown"

            # Optional live carrier lookup (only runs if 'numverify' key exists in config.yaml)
            live_info = self._fetch_live_numverify(e164_fmt)
            dorks = self._build_dorks(e164_fmt, nat_fmt)

            core_findings = {
                "E164_FORMAT": e164_fmt,
                "INTERNATIONAL_FORMAT": intl_fmt,
                "NATIONAL_FORMAT": nat_fmt,
                "COUNTRY_CODE": f"+{parsed.country_code} ({region_code})",
                "LOCATION": location,
                "CARRIER_OFFLINE": telecom_carrier,
                "LINE_TYPE": line_type,
                "TIMEZONE": tz_str,
            }
            core_findings.update(live_info)

            for f_type, f_val in core_findings.items():
                self.db.add_osint_finding(e164_fmt, "PHONE", "phone_osint", f_type, f_val)

            for d_type, d_url in dorks.items():
                self.db.add_osint_finding(e164_fmt, "PHONE", "phone_osint", d_type, d_url)

            self.db.log_action(
                "PHONE_OSINT_COMPLETE",
                f"Target: {e164_fmt} | Region: {region_code} | Carrier: {telecom_carrier} | Type: {line_type}",
            )

            results.update({
                "valid": True,
                "e164": e164_fmt,
                "core": core_findings,
                "dorks": dorks,
            })

        except phonenumbers.NumberParseException as e:
            self.db.add_osint_finding(raw_number, "PHONE", "phone_osint", "STATUS", f"Parse Error: {str(e)}")
            results["error"] = f"Could not parse phone number: {str(e)}"
        except Exception as e:
            results["error"] = f"Phone OSINT error: {str(e)}"

        return results