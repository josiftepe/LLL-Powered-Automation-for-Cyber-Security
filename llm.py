import os
from typing import List, Dict
import json
import requests
from ThreatReportItem import ThreatReportItem
class LLM:
    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model
        self.key = os.getenv("OPENAI_API_KEY")

    def available(self) -> bool:
        return bool(self.key)

    def judge(self, batch: List[ThreatReportItem]) -> List[Dict]:
        if not self.available() or not batch:
            return []

        system = (
            "You are a security analyst.\n"
            "For each candidate, determine whether it is: secret, benign, or unclear.\n"
            "Return ONLY a JSON array. Each element must follow:\n"
            "{\n"
            "  \"verdict\": \"secret\" | \"benign\" | \"unclear\",\n"
            "  \"type\": \"<short category>\",\n"
            "  \"rationale\": \"<1–2 short sentences>\",\n"
            "  \"confidence\": <float 0–1>\n"
            "}\n"
            "Guidance:\n"
            "- secret → real credential or sensitive token.\n"
            "- benign → example, placeholder, or unrelated.\n"
            "- unclear → insufficient context.\n"
            "Do not include extra commentary outside the JSON array."
        )

        def item_to_text(f: ThreatReportItem) -> str:
            return (
                f"commit={f.commit[:10]} file={f.file} line={f.line} detector={f.detector} "
                f"snippet={json.dumps(f.snippet)}"
            )

        user = "\n".join([item_to_text(f) for f in batch])



        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}

        try:
            resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            data = resp.json()

            content = data["choices"][0]["message"]["content"]
            print(content)
            parsed = json.loads(content)
            items = parsed.get("items") or parsed.get("results") or parsed
            if isinstance(items, dict) and "items" in items:
                items = items["items"]
            if isinstance(items, list):
                out: List[Dict] = []
                for it in items:
                    out.append({
                        "verdict": it.get("verdict", "unclear"),
                        "type": it.get("type", "unknown"),
                        "rationale": it.get("rationale", ""),
                        "confidence": float(it.get("confidence", 0.5)),
                    })
                return out
        except Exception as e:
            return []
        return []