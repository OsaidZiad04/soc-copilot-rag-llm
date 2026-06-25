import json
from typing import Any, Dict


class OutputFormatter:

    def __init__(self):
        self.base = {
            "summary": "",
            "attack_type": "unknown",
            "risk_level": "info",
            "ioc": [],
            "recommendations": [],
            "confidence": 0.0,
        }

    def parse_json_or_none(self, text: str):
        if not text:
            return None

        try:
            return json.loads(text)
        except Exception:
            pass

        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except Exception:
                return None
        return None

    def to_structured(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(self.base)
        if isinstance(payload, dict):
            result.update(payload)

        if not isinstance(result.get("ioc"), list):
            result["ioc"] = []
        if not isinstance(result.get("recommendations"), list):
            result["recommendations"] = []

        try:
            result["confidence"] = float(result.get("confidence", 0.0))
        except Exception:
            result["confidence"] = 0.0

        return result

