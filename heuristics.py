from typing import Dict, List, Optional
import math
import re
from ThreatReportItem import ThreatReportItem
class HeuristicDetector:
    AWS_ACCESS_KEY_ID = re.compile(r'''AKIA[0-9A-Z]{16}''')
    AWS_SECRET_ACCESS_KEY = re.compile(r'''(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*([A-Za-z0-9/+=]{40})''')
    GITHUB_PAT = re.compile(r'''ghp_[A-Za-z0-9]{36}''')
    SLACK_BOT_TOKEN = re.compile(r'''xoxb-\d{11}-\d{11}-[A-Za-z0-9]{24}''')
    GOOGLE_API_KEY = re.compile(r'''AIza[0-9A-Za-z\-_]{35}''')
    STRIPE_SK = re.compile(r'''sk_live_[0-9a-zA-Z]{24}''')

    BASE64ISH = re.compile(r'''^[A-Za-z0-9+/=]{16,}$''')
    HEXISH = re.compile(r'''^[A-Fa-f0-9]{16,}$''')

    GENERIC_KEYWORDS = [
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
        "private_key", "ssh-rsa", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
        "client_secret", "db_password", "jwt_secret", "auth"
    ]

    def __init__(self, min_entropy: float = 4.0, min_length: int = 16):
        self.min_entropy = min_entropy
        self.min_length = min_length
        self.signatures = {
            "aws_access_key_id": self.AWS_ACCESS_KEY_ID,
            "aws_secret_key": self.AWS_SECRET_ACCESS_KEY,
            "github_pat": self.GITHUB_PAT,
            "slack_bot": self.SLACK_BOT_TOKEN,
            "google_api_key": self.GOOGLE_API_KEY,
            "stripe_secret": self.STRIPE_SK,
        }

    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        total = len(s)
        ent = 0.0
        for c in freq.values():
            p = c / total
            ent -= p * math.log2(p)
        return ent

    def looks_secret_token(self, token: str) -> bool:
        if len(token) < self.min_length:
            return False
        alnum_mix = bool(re.search(r'''[A-Za-z]''', token) and re.search(r'''\d''', token))
        if not (self.BASE64ISH.match(token) or self.HEXISH.match(token) or alnum_mix):
            return False
        return self.shannon_entropy(token) >= self.min_entropy

    @staticmethod
    def split_candidates(s: str) -> List[str]:
        raw = re.split(r'''[\s'\"=,:]''', s)
        return [t.strip() for t in raw if len(t.strip()) >= 4]

    def scan_diff(self, commit: str, diff: str) -> List[ThreatReportItem]:
        findings: List[ThreatReportItem] = []
        current_file: Optional[str] = None
        current_line: Optional[int] = None

        for line in diff.splitlines():
            if line.startswith("+++ "):
                path = line[4:].strip()
                if path.startswith("b/"):
                    path = path[2:]
                current_file = path
                continue
            if line.startswith("@@ "):
                m = re.search(r"\+(\d+)", line)
                current_line = int(m.group(1)) if m else 0
                continue
            if not line.startswith("+") or line.startswith("+++ "):
                continue

            added = line[1:]
            if current_file is None or current_line is None:
                continue

            for name, pat in self.signatures.items():
                for match in pat.finditer(added):
                    s = match.group(0)
                    col = match.start()
                    findings.append(ThreatReportItem(
                        commit=commit,
                        file=current_file,
                        line=current_line,
                        offset=col,
                        snippet=s if len(s) < 240 else s[:240] + "…",
                        finding_type="credential",
                        detector=f"regex:{name}",
                        rationale=f"Matched known pattern {name} in added line.",
                        confidence=0.9,
                    ))

            lowered = added.lower()
            if any(k in lowered for k in (k.lower() for k in self.GENERIC_KEYWORDS)):
                for token in self.split_candidates(added):
                    if self.looks_secret_token(token):
                        col = added.find(token)
                        findings.append(ThreatReportItem(
                            commit=commit,
                            file=current_file,
                            line=current_line,
                            offset=col,
                            snippet=(token if len(token) < 240 else token[:240] + "…"),
                            finding_type="potential_secret",
                            detector="entropy+keyword",
                            rationale="High-entropy token near sensitive keyword.",
                            confidence=0.6,
                        ))

            current_line += 1

        return findings