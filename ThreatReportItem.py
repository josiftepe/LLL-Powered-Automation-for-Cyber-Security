from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class ThreatReportItem:
    commit: str
    file: str
    line: int
    offset: int
    snippet: str
    finding_type: str
    detector: str
    rationale: str
    confidence: float
    llm: Optional[Dict] = None