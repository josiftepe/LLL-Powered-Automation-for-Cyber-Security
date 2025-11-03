from typing import List, Optional
import re
from ThreatReportItem import ThreatReportItem
from git_helper_utils import GitHelper
from heuristics import HeuristicDetector
from llm import LLM
class ScannerCore:
    def __init__(self, repo: GitHelper, detector: HeuristicDetector, llm: Optional[LLM] = 'gpt-4o-mini'):
        self.repo = repo
        self.detector = detector
        self.llm = llm

    def scan_commits(self, n: int) -> List[ThreatReportItem]:
        commits = self.repo.list_last_commits(n)
        all_findings: List[ThreatReportItem] = []

        for commit in commits[::-1]:
            parent = self.repo.commit_parent(commit)
            diff = self.repo.diff_added(parent, commit)
            findings = self.detector.scan_diff(commit, diff)

            msg = self.repo.commit_message(commit)
            if any(k in msg.lower() for k in (k.lower() for k in self.detector.GENERIC_KEYWORDS)):
                snippet = msg.strip()
                snippet = snippet[:240] + ("…" if len(snippet) > 240 else "")
                findings.append(ThreatReportItem(
                    commit=commit,
                    file="<commit-message>",
                    line=0,
                    offset=0,
                    snippet=snippet,
                    finding_type="suspicious_commit_message",
                    detector="keyword",
                    rationale="Sensitive keyword present in commit message.",
                    confidence=0.4,
                    llm=self.llm
                ))

            if self.llm and self.llm.available() and findings:
                B = 12
                for i in range(0, len(findings), B):
                    batch = findings[i:i+B]
                    judgments = self.llm.judge(batch)
                    if judgments and len(judgments) == len(batch):
                        for f, j in zip(batch, judgments):
                            f.llm = {
                                "model": self.llm.model,
                                "verdict": j.get("verdict", "unclear"),
                                "type": j.get("type", "unknown"),
                                "rationale": j.get("rationale", ""),
                                "confidence": float(j.get("confidence", 0.5)),
                            }
                            verdict = f.llm["verdict"]
                            if verdict == "secret":
                                f.confidence = max(f.confidence, min(0.99, 0.6 + 0.4 * f.llm["confidence"]))
                            elif verdict == "benign":
                                f.confidence = min(f.confidence, 0.3 * (1 - f.llm["confidence"]))

            all_findings.extend(findings)

        return all_findings