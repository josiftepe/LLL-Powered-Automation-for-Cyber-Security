import argparse
from git_helper_utils import GitHelper
from heuristics import HeuristicDetector
from llm import  LLM
from scanner_core import ScannerCore
from dataclasses import  asdict
import json

def main():
    ap = argparse.ArgumentParser(description="Scan last N commits for secrets and sensitive data")
    ap.add_argument("--repo", required=True, help="Path or git URL to repository")
    ap.add_argument("--n", type=int, default=50, help="Number of commits to scan (default: 50)")
    ap.add_argument("--out", required=True, help="Path to output JSON report")
    ap.add_argument("--model", default="gpt-4o-mini", help="LLM model id (used if an API key is available)")
    args = ap.parse_args()

    repo = GitHelper(args.repo, depth_hint=args.n)
    detector = HeuristicDetector(min_entropy=4.0, min_length=16)
    llm = LLM(model=args.model)

    scanner = ScannerCore(repo=repo, detector=detector, llm=llm)

    try:
        findings = scanner.scan_commits(args.n)
        data = [asdict(f) for f in findings]
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"Found # {len(findings)} possible threats to {args.out}")
    finally:
        repo.cleanup()

if __name__ == "__main__":
    main()