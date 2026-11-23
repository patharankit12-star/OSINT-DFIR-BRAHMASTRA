import urllib.parse
from typing import Any, Dict
import phonenumbers
from phonenumbers import carrier, geocoder, timezone, PhoneNumberType

from core.database import CaseDatabase


class PhoneOSINT:
    """
    Engine 3 (Part A): Performs offline telecom intelligence, VoIP detection,
    and passive OSINT dork generation for Indian and International phone numbers.
    """

    # Map phonenumbers type codes to human-readable labels
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

    def __init__(self, db: CaseDatabase):
        # Connect this module to the active SQLite case database
        self.db = db

    def _build_dorks(self, e164_num: str, national_num: str) -> Dict[str, str]:
        # Generate ready-to-use passive OSINT links and Google Dorks
        digits_only = e164_num.lstrip("+")
        clean_national = national_num.replace(" ", "").replace("-", "")

        # Google Dork queries covering general web, social media, and document/paste leaks
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
        """
        Parses a phone number, extracts telecom/location/VoIP metadata,
        generates OSINT dorks, and saves everything to the SQLite Case DB.
        """
        raw_number = raw_number.strip()
        results: Dict[str, Any] = {"raw_input": raw_number, "valid": False}

        try:
            # Parse number (uses default_region="IN" if user omits +91)
            parsed = phonenumbers.parse(raw_number, default_region)
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

            # Extract location, original carrier, line type, and timezones
            region_code = phonenumbers.region_code_for_number(parsed) or "Unknown"
            location = geocoder.description_for_number(parsed, "en") or "Unknown"
            telecom_carrier = carrier.name_for_number(parsed, "en") or "Unknown / Ported"
            num_type_code = phonenumbers.number_type(parsed)
            line_type = self.LINE_TYPE_MAP.get(num_type_code, "UNKNOWN")
            tz_list = list(timezone.time_zones_for_number(parsed))
            tz_str = ", ".join(tz_list) if tz_list else "Unknown"

            # Build OSINT dorks and messaging links
            dorks = self._build_dorks(e164_fmt, nat_fmt)

            # Save all core telecom findings to SQLite DB
            core_findings = {
                "E164_FORMAT": e164_fmt,
                "INTERNATIONAL_FORMAT": intl_fmt,
                "NATIONAL_FORMAT": nat_fmt,
                "COUNTRY_CODE": f"+{parsed.country_code} ({region_code})",
                "LOCATION": location,
                "CARRIER": telecom_carrier,
                "LINE_TYPE": line_type,
                "TIMEZONE": tz_str,
            }

            for f_type, f_val in core_findings.items():
                self.db.add_osint_finding(e164_fmt, "PHONE", "phone_osint", f_type, f_val)

            # Save messaging links and Google Dorks
            for d_type, d_url in dorks.items():
                self.db.add_osint_finding(e164_fmt, "PHONE", "phone_osint", d_type, d_url)

            # Log completion in Chain of Custody
            self.db.log_action(
                "PHONE_OSINT_COMPLETE",
                f"Target: {e164_fmt} | Location: {location} | Carrier: {telecom_carrier} | Type: {line_type}",
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