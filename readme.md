# LLMDetectorForCyberThreats — LLM-Assisted Git Secret Detector

LLMDetectorForCyberThreats scans the last **N commits** of a Git repository to detect credentials or other sensitive data. It uses fast heuristics (regex + entropy + keywords) and can optionally call an LLM to reduce false positives.

---

## Features

* Scans added lines + commit messages
* Detects AWS, GitHub PAT, Slack, Stripe, Google keys, etc.
* Generic high-entropy token matching
* Optional LLM verification (`OPENAI_API_KEY`)
* Works on local paths or remote Git URLs (auto-clone)
* Outputs JSON report (`ThreatReportItem[]`)

---

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

(Optional)

```bash
export OPENAI_API_KEY="sk-..."
```

---

## Usage

### Remote repo

```bash
python scan.py \
  --repo https://github.com/... \
  --n 50 \
  --out report.json
```

---

## Output

Each item in `report.json` has:

```
{
  commit, file, line, offset,
  snippet, finding_type, detector,
  rationale, confidence,
  llm: { verdict, type, rationale, confidence } | null
}
```

---

## Structure

* GitHelper — commit + diff access
* HeuristicDetector — regex/keywords/entropy
* LLM — optional classification

---

## Why

This tool reduces manual triage by combining reliable heuristics with LLM-based validation, improving precision while keeping noise low.

---

MIT License
