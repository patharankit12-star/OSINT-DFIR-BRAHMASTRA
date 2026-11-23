import json
import re
from typing import Any, Dict, List
from google import genai

from core.config import ConfigManager


class AIBrain:
    """
    Uses Gemini API with dynamic model auto-discovery to analyze DFIR/OSINT evidence
    and recommend the next high-value pivot targets.
    """

    def __init__(self, config: ConfigManager):
        self.api_key = config.get_api_key("gemini")
        self.client = genai.Client(api_key=self.api_key) if self.api_key else None

    def _clean_json_response(self, raw_text: str) -> str:
        # Remove markdown code fences (```json ... ```) if present
        cleaned = re.sub(r"^```(?:json)?\s*", "", raw_text.strip(), flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        return cleaned.strip()

    def _discover_flash_models(self) -> List[str]:
        # Dynamically fetch active Gemini Flash text models available for this API key
        discovered = []
        skip_keywords = ("image", "audio", "tts", "video", "embedding", "robotics", "computer")
        try:
            for m in self.client.models.list():
                name = m.name.replace("models/", "")
                lower_name = name.lower()
                if "gemini" in lower_name and "flash" in lower_name:
                    if not any(bad in lower_name for bad in skip_keywords):
                        discovered.append(name)
        except Exception:
            pass

        # Fallback defaults if listing fails
        return discovered if discovered else ["gemini-2.5-flash", "gemini-2.0-flash"]

    def decide_next_pivots(
        self,
        iocs: List[Dict[str, str]],
        secrets: List[Dict[str, str]],
        osint_findings: List[Dict[str, str]],
        visited_targets: set,
    ) -> Dict[str, Any]:
        if not self.client:
            return {
                "summary": "Gemini API key not configured in config.yaml. Skipping AI pivot.",
                "pivots": [],
            }

        evidence_payload = {
            "iocs": iocs[:40],
            "secrets": secrets[:20],
            "osint_findings": osint_findings[:50],
            "already_scanned_targets": list(visited_targets),
        }

        prompt = f"""
You are an elite DFIR and OSINT investigator. Analyze the following case evidence JSON.
Identify the highest-value NEXT pivot targets that have NOT been scanned yet.

Rules:
1. Extract clean usernames from local paths (e.g., '/home/rahul_scammer/Desktop' -> USERNAME: 'rahul_scammer').
2. Extract clean domains from URLs or custom emails (ignore gmail.com, protonmail.com, outlook.com for DOMAIN recon, but keep them for EMAIL recon).
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

        candidate_models = self._discover_flash_models()
        errors = []

        # Try up to 4 discovered models until one returns valid JSON
        for model_name in candidate_models[:4]:
            try:
                response = self.client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                )
                cleaned_json = self._clean_json_response(response.text)
                parsed = json.loads(cleaned_json)
                return {
                    "summary": f"[{model_name}] " + parsed.get("summary", "No summary provided."),
                    "pivots": parsed.get("pivots", [])[:5],
                }
            except Exception as e:
                errors.append(f"{model_name} -> {str(e)[:120]}")
                continue

        return {
            "summary": "All Gemini models failed: " + " | ".join(errors),
            "pivots": [],
        }