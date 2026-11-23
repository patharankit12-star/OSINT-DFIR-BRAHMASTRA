import json
import re
from typing import Any, Dict, List
from google import genai

from core.config import ConfigManager


class AIBrain:
    """
    Uses Gemini API to analyze collected DFIR/OSINT evidence and recommend
    the next high-value pivot targets (Domains, Emails, Usernames).
    """

    def __init__(self, config: ConfigManager):
        self.api_key = config.get_api_key("gemini")
        self.client = genai.Client(api_key=self.api_key) if self.api_key else None
        # Fast, free-tier friendly Gemini model for structured reasoning
        self.model_name = "gemini-2.5-flash"

    def _clean_json_response(self, raw_text: str) -> str:
        # Remove markdown code fences (```json ... ```) if the model includes them
        cleaned = re.sub(r"^```(?:json)?\s*", "", raw_text.strip(), flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        return cleaned.strip()

    def decide_next_pivots(
        self,
        iocs: List[Dict[str, str]],
        secrets: List[Dict[str, str]],
        osint_findings: List[Dict[str, str]],
        visited_targets: set,
    ) -> Dict[str, Any]:
        """
        Reads all case evidence and returns a structured JSON with:
        - summary: short investigative assessment
        - pivots: list of next targets to scan (DOMAIN, EMAIL, USERNAME)
        """
        if not self.client:
            return {
                "summary": "Gemini API key not configured. Skipping AI pivot reasoning.",
                "pivots": [],
            }

        # Prepare a compact evidence snapshot so we stay well within token limits
        evidence_payload = {
            "iocs": iocs[:40],
            "secrets": secrets[:20],
            "osint_findings": osint_findings[:50],
            "already_scanned_targets": list(visited_targets),
        }

        prompt = f"""
You are an elite DFIR and OSINT investigator. Analyze the following case evidence JSON.
Your job is to identify the highest-value NEXT pivot targets that have NOT been scanned yet.

Rules:
1. Extract clean usernames from local paths (e.g., '/home/rahul_scammer/Desktop' -> USERNAME: 'rahul_scammer').
2. Extract clean domains from URLs or custom emails (ignore common public providers like gmail.com, protonmail.com, outlook.com for DOMAIN recon, but keep them for EMAIL recon).
3. NEVER recommend any target already listed in 'already_scanned_targets'.
4. Allowed target_type values ONLY: "DOMAIN", "EMAIL", "USERNAME".
5. Return ONLY valid JSON (no markdown, no extra text) in this exact format:
{{
  "summary": "2-3 sentence assessment of what the evidence currently points to.",
  "pivots": [
    {{
      "source_clue": "exact clue from evidence",
      "target": "clean target value",
      "target_type": "DOMAIN or EMAIL or USERNAME",
      "reason": "short reason why pivoting here matters"
    }}
  ]
}}

Case Evidence:
{json.dumps(evidence_payload, indent=2)}
"""

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
            )
            cleaned_json = self._clean_json_response(response.text)
            parsed = json.loads(cleaned_json)
            return {
                "summary": parsed.get("summary", "No summary provided."),
                "pivots": parsed.get("pivots", [])[:5],  # Max 5 pivots per depth to stay fast
            }
        except Exception as e:
            return {
                "summary": f"AI Brain encountered an error: {str(e)}",
                "pivots": [],
            }