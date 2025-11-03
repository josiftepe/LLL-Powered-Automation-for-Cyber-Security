import dataclasses
from dataclasses import dataclass, asdict
from typing import Optional, Dict


@dataclass
class ThreatResponse:
    commit: str
    file: str
    line: int
    offset: int
    snippet: str
    threat_response_type: str
    detector: str
    rationale: str
    confidence: float
    llm: Optional[Dict] = None