#!/usr/bin/env python3
"""A tiny demo static analyzer for C/C++ CWE-oriented coursework.

It is intentionally conservative and explainable: it extracts simple facts from C/C++
source text, applies hand-written rules, and emits JSON/Markdown/SARIF/facts that can
be fed to Souffle for a formal Datalog demonstration.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}


@dataclasses.dataclass(frozen=True)
class Finding:
    rule_id: str
    cwe: str
    severity: str
    file: str
    line: int
    message: str
    evidence: str
    recommendation: str


RULES = {
    "DEMO-CWE-120-CIN-CHAR-ARRAY": {
        "name": "Unbounded formatted extraction into char array",
        "cwe": "CWE-120/CWE-787",
        "shortDescription": "cin >> char[] can overflow the fixed-size buffer.",
        "help": "Use std::string, std::setw(sizeof(buf)), or bounded parsing.",
    },
    "DEMO-CWE-120-STRCPY": {
        "name": "Unsafe C string copy",
        "cwe": "CWE-120/CWE-787",
        "shortDescription": "strcpy copies until NUL without checking destination capacity.",
        "help": "Use std::string, strncpy_s on Windows, or copy with explicit bounds and NUL termination.",
    },
    "DEMO-CWE-20-SCANF-RETURN": {
        "name": "Unchecked scanf result",
        "cwe": "CWE-20/CWE-252",
        "shortDescription": "scanf return value is ignored, so invalid input may leave the variable unchanged.",
        "help": "Check scanf's return value and reject invalid input.",
    },
    "DEMO-CWE-787-INPUT-BOUND": {
        "name": "Unvalidated input used as array bound/index limit",
        "cwe": "CWE-20/CWE-787",
        "shortDescription": "User-controlled numeric input is used as a loop bound for fixed-size arrays.",
        "help": "Validate the input range before it controls array access, for example 1 <= nums <= 7.",
    },
    "DEMO-CWE-330-RAND": {
        "name": "Weak random number generator",
        "cwe": "CWE-330",
        "shortDescription": "rand() is predictable and not suitable for security-sensitive randomness.",
        "help": "Use a CSPRNG for security; if this is only simulation data, document that it is non-security randomness.",
    },
    "DEMO-CWE-362-THREAD": {
        "name": "Thread lifecycle / race-prone Windows API use",
        "cwe": "CWE-362/CWE-667",
        "shortDescription": "TerminateThread/SuspendThread can leave shared state inconsistent and is race-prone.",
        "help": "Prefer cooperative cancellation, joins, condition variables, and scoped locks.",
    },
    "DEMO-CWE-398-BUILD-BUG": {
        "name": "Likely build or logic typo",
        "cwe": "CWE-398",
        "shortDescription": "Suspicious operator or case mismatch likely prevents correct build or output.",
        "help": "Fix the typo and add CI compilation checks.",
    },
}


def read_text(path: Path) -> str:
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return path.read_bytes().decode("latin-1", errors="replace")


def iter_source_files(root: Path) -> Iterable[Path]:
    if root.is_file() and root.suffix.lower() in SOURCE_EXTS:
        yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in SOURCE_EXTS:
            yield p


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base)).replace(os.sep, "/")
    except ValueError:
        return str(path).replace(os.sep, "/")


def add(findings: List[Finding], rule_id: str, file: str, line: int, message: str, evidence: str, recommendation: str, severity: str = "warning") -> None:
    findings.append(Finding(rule_id, RULES[rule_id]["cwe"], severity, file, line, message, evidence.strip(), recommendation))


def split_cin_targets(expr: str) -> List[str]:
    # Handles simple cases such as cin>>command; and cin >> name >> time;
    expr = expr.split(";", 1)[0]
    pieces = [x.strip() for x in expr.split(">>")]
    targets = []
    for piece in pieces[1:]:
        m = re.match(r"([A-Za-z_]\w*)", piece)
        if m:
            targets.append(m.group(1))
    return targets


def analyze_file(path: Path, base: Path) -> Tuple[List[Finding], Dict[str, List[Tuple]]]:
    text = read_text(path)
    lines = text.splitlines()
    file = rel(path, base)
    findings: List[Finding] = []
    facts: Dict[str, List[Tuple]] = {
        "array_decl": [],
        "unbounded_read": [],
        "unsafe_call": [],
        "untrusted_int": [],
        "var_as_bound": [],
    }

    char_arrays: Dict[str, int] = {}
    array_dims: Dict[str, Tuple[int, ...]] = {}
    scanf_int_vars: Dict[str, int] = {}

    for i, line in enumerate(lines, start=1):
        for m in re.finditer(r"\bchar\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]", line):
            char_arrays[m.group(1)] = int(m.group(2))
            facts["array_decl"].append((file, i, m.group(1), int(m.group(2))))
        for m in re.finditer(r"\b(?:int|char|long|short|float|double)\s+([A-Za-z_]\w*)\s*((?:\[\s*\d+\s*\])+)", line):
            dims = tuple(int(x) for x in re.findall(r"\d+", m.group(2)))
            array_dims[m.group(1)] = dims
            for d in dims:
                facts["array_decl"].append((file, i, m.group(1), d))

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        if "cin" in stripped and ">>" in stripped:
            for target in split_cin_targets(stripped):
                if target in char_arrays:
                    facts["unbounded_read"].append((file, i, target, "cin"))
                    add(
                        findings,
                        "DEMO-CWE-120-CIN-CHAR-ARRAY",
                        file,
                        i,
                        f"`cin >> {target}` writes into fixed char[{char_arrays[target]}] without a width limit.",
                        stripped,
                        "Replace the buffer with std::string, or use std::setw(buffer_size) before extraction.",
                        "error",
                    )

        if re.search(r"\bstrcpy\s*\(", stripped):
            facts["unsafe_call"].append((file, i, "strcpy", "CWE-120"))
            add(
                findings,
                "DEMO-CWE-120-STRCPY",
                file,
                i,
                "`strcpy` copies attacker/user-controlled strings without checking destination capacity.",
                stripped,
                "Use std::string or a bounded copy routine and explicitly check destination size.",
                "error",
            )

        sm = re.search(r'\bscanf\s*\(\s*"([^"]*)"\s*,\s*&\s*([A-Za-z_]\w*)', stripped)
        if sm and "%d" in sm.group(1):
            var = sm.group(2)
            scanf_int_vars[var] = i
            facts["untrusted_int"].append((file, i, var, "scanf"))
            add(
                findings,
                "DEMO-CWE-20-SCANF-RETURN",
                file,
                i,
                f"Return value of `scanf` is ignored when reading `{var}`.",
                stripped,
                "Require `scanf(...) == 1`; reject non-numeric input and initialize variables safely.",
            )

        if re.search(r"\b(rand)\s*\(", stripped):
            facts["unsafe_call"].append((file, i, "rand", "CWE-330"))
            add(
                findings,
                "DEMO-CWE-330-RAND",
                file,
                i,
                "`rand()` is predictable; do not use it for security-sensitive randomness.",
                stripped,
                "For simulation this is acceptable if documented; otherwise use a CSPRNG.",
                "note",
            )

        for api in ("TerminateThread", "SuspendThread"):
            if re.search(rf"\b{api}\s*\(", stripped):
                facts["unsafe_call"].append((file, i, api, "CWE-362"))
                add(
                    findings,
                    "DEMO-CWE-362-THREAD",
                    file,
                    i,
                    f"Use of `{api}` can interrupt code while locks or shared state are inconsistent.",
                    stripped,
                    "Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.",
                )

        if '<"--"' in stripped or '<"--";' in stripped or 'name<"--"' in stripped:
            add(
                findings,
                "DEMO-CWE-398-BUILD-BUG",
                file,
                i,
                "Suspicious `<` appears where stream insertion `<<` was probably intended.",
                stripped,
                "Change `<` to `<<` and add a compilation job to CI.",
                "warning",
            )
        if '#include "schedule.h"' in stripped and file.endswith("003.main.cpp"):
            add(
                findings,
                "DEMO-CWE-398-BUILD-BUG",
                file,
                i,
                "Linux/Arch is case-sensitive: source includes `schedule.h`, but sample file is `Schedule.h`.",
                stripped,
                "Rename the include or the file so GitHub Actions/Linux can compile it.",
                "warning",
            )

    # Cross-line heuristic: scanf-controlled variable controls loops over fixed arrays.
    for var, scanf_line in scanf_int_vars.items():
        range_check = re.compile(rf"\b{re.escape(var)}\b\s*(<=|<|>=|>)\s*\d+|\d+\s*(<=|<|>=|>)\s*\b{re.escape(var)}\b")
        has_nearby_range_check = any(range_check.search(x) and "printf" not in x for x in lines[max(0, scanf_line - 1): min(len(lines), scanf_line + 12)])
        for i, line in enumerate(lines, start=1):
            if re.search(rf"for\s*\([^;]*;[^;]*<\s*{re.escape(var)}\b", line):
                # Search a short following window for array access with an induction variable.
                window = "\n".join(lines[i - 1:min(len(lines), i + 8)])
                for arr, dims in array_dims.items():
                    if re.search(rf"\b{re.escape(arr)}\s*\[[^\]]+\]\s*\[[^\]]+\]", window) or re.search(rf"\b{re.escape(arr)}\s*\[[^\]]+\]", window):
                        cap = dims[-1]
                        facts["var_as_bound"].append((file, i, var, arr, cap))
                        if not has_nearby_range_check:
                            add(
                                findings,
                                "DEMO-CWE-787-INPUT-BOUND",
                                file,
                                i,
                                f"Input variable `{var}` controls a loop that indexes fixed array `{arr}` with capacity {cap}.",
                                line.strip(),
                                f"Validate `{var}` before the loop, e.g. `if ({var} < 1 || {var} > {cap}) return;`.",
                                "error",
                            )
                        break

    return findings, facts


def make_sarif(findings: List[Finding]) -> dict:
    rules = []
    for rid, meta in RULES.items():
        rules.append({
            "id": rid,
            "name": meta["name"],
            "shortDescription": {"text": meta["shortDescription"]},
            "fullDescription": {"text": f"Maps to {meta['cwe']}."},
            "help": {"text": meta["help"]},
            "properties": {"tags": ["security", meta["cwe"]]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": "error" if f.severity == "error" else ("note" if f.severity == "note" else "warning"),
            "message": {"text": f"{f.cwe}: {f.message} Recommendation: {f.recommendation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "coursework-cwe-static-analyzer", "informationUri": "https://cwe.mitre.org/", "rules": rules}},
            "results": results,
        }],
    }


def write_facts(facts: Dict[str, List[Tuple]], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for name, rows in facts.items():
        with (outdir / f"{name}.facts").open("w", encoding="utf-8") as f:
            for row in rows:
                f.write("\t".join(str(x).replace("\t", " ") for x in row) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default="samples", help="Source root or single source file")
    ap.add_argument("--json", default="analysis/findings.json")
    ap.add_argument("--markdown", default="analysis/report.md")
    ap.add_argument("--sarif", default="analysis/custom-cwe.sarif")
    ap.add_argument("--facts", default="analysis/facts")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    base = root if root.is_dir() else root.parent
    all_findings: List[Finding] = []
    merged_facts: Dict[str, List[Tuple]] = {k: [] for k in ["array_decl", "unbounded_read", "unsafe_call", "untrusted_int", "var_as_bound"]}

    for src in sorted(iter_source_files(root)):
        findings, facts = analyze_file(src, base)
        all_findings.extend(findings)
        for k, rows in facts.items():
            merged_facts.setdefault(k, []).extend(rows)

    all_findings.sort(key=lambda f: (f.file, f.line, f.rule_id))

    json_path = Path(args.json)
    md_path = Path(args.markdown)
    sarif_path = Path(args.sarif)
    for p in (json_path, md_path, sarif_path):
        p.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(json.dumps([dataclasses.asdict(f) for f in all_findings], ensure_ascii=False, indent=2), encoding="utf-8")
    sarif_path.write_text(json.dumps(make_sarif(all_findings), ensure_ascii=False, indent=2), encoding="utf-8")
    write_facts(merged_facts, Path(args.facts))

    lines = ["# CWE 静态分析报告", "", f"共发现 **{len(all_findings)}** 个告警。", ""]
    for f in all_findings:
        lines.extend([
            f"## {f.cwe} · {f.file}:{f.line}",
            "",
            f"- 规则：`{f.rule_id}`",
            f"- 严重性：`{f.severity}`",
            f"- 说明：{f.message}",
            f"- 证据：`{f.evidence}`",
            f"- 建议：{f.recommendation}",
            "",
        ])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(all_findings)} findings")
    print(f"- {json_path}")
    print(f"- {md_path}")
    print(f"- {sarif_path}")
    print(f"- {Path(args.facts)}")
    return 1 if any(f.severity == "error" for f in all_findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
