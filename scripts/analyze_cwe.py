#!/usr/bin/env python3
"""Orchestrate the coursework CWE analyzer pipeline.

Pipeline:
  1. Python/AST/regex front-end extracts Souffle facts from source code.
  2. Souffle Datalog rules infer CWE findings from those facts.
  3. A converter emits JSON, Markdown and SARIF.
  4. If Souffle is unavailable, a Python fallback mirrors the Datalog rules so
     Chromebook/GitHub demonstrations remain stable.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+ " + " ".join(cmd))
    return subprocess.run(cmd, text=True, check=check)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run fact extraction, Souffle inference, and report generation")
    ap.add_argument("root", nargs="?", default="samples", help="Source root or single source file")
    ap.add_argument("--json", default="analysis/findings.json")
    ap.add_argument("--markdown", default="analysis/report.md")
    ap.add_argument("--sarif", default="analysis/custom-cwe.sarif")
    ap.add_argument("--facts", default="analysis/facts")
    ap.add_argument("--datalog", default="analysis/datalog")
    ap.add_argument("--rules", default="rules/cwe_rules.dl")
    ap.add_argument("--no-souffle", action="store_true", help="Skip Souffle and use Python fallback inference")
    args = ap.parse_args()

    facts_dir = Path(args.facts)
    datalog_dir = Path(args.datalog)
    finding_csv = datalog_dir / "finding.csv"
    facts_dir.mkdir(parents=True, exist_ok=True)
    datalog_dir.mkdir(parents=True, exist_ok=True)

    run([sys.executable, "scripts/extract_facts.py", args.root, "--facts", str(facts_dir)])

    engine = "souffle"
    use_souffle = (not args.no_souffle) and shutil.which("souffle") is not None
    if use_souffle:
        try:
            run(["souffle", "-F", str(facts_dir), "-D", str(datalog_dir), args.rules])
        except subprocess.CalledProcessError:
            print("Souffle failed; falling back to Python rule mirror.", file=sys.stderr)
            engine = "python-fallback-after-souffle-failure"
            proc = run([sys.executable, "scripts/facts_to_results.py", "--facts", str(facts_dir), "--datalog", str(finding_csv), "--fallback", "--engine", engine, "--json", args.json, "--markdown", args.markdown, "--sarif", args.sarif], check=False)
            return proc.returncode
    else:
        reason = "disabled" if args.no_souffle else "not installed"
        print(f"Souffle {reason}; using Python fallback that mirrors rules/cwe_rules.dl.")
        engine = "python-fallback-equivalent-to-souffle-rules"
        # facts_to_results will create finding.csv before converting outputs.
        proc = run([sys.executable, "scripts/facts_to_results.py", "--facts", str(facts_dir), "--datalog", str(finding_csv), "--fallback", "--json", args.json, "--markdown", args.markdown, "--sarif", args.sarif], check=False)
        return proc.returncode

    proc = run([sys.executable, "scripts/facts_to_results.py", "--facts", str(facts_dir), "--datalog", str(finding_csv), "--engine", engine, "--json", args.json, "--markdown", args.markdown, "--sarif", args.sarif], check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
