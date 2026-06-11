#!/usr/bin/env python3
"""Convert Souffle CWE inference output into JSON, Markdown and SARIF.

The preferred path is:
  extract_facts.py -> souffle rules/cwe_rules.dl -> finding.csv -> this script

For machines without Souffle, this script also contains a small fallback engine
that mirrors the Datalog rules.  The fallback keeps Chromebook/GitHub demos
stable, but the formal relation remains documented in rules/cwe_rules.dl.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import json
from pathlib import Path
from typing import Any

FINDING_COLUMNS = [
    "file",
    "line",
    "language",
    "cwe",
    "rule_id",
    "severity",
    "message",
    "evidence",
    "recommendation",
]

RULES: dict[str, dict[str, str]] = {
    "DEMO-CWE-120-CIN-CHAR-ARRAY": {"name": "Unbounded formatted extraction into char array", "cwe": "CWE-120/CWE-787", "shortDescription": "cin >> char[] can overflow the fixed-size buffer.", "help": "Use std::string, std::setw(sizeof(buf)), or bounded parsing."},
    "DEMO-CWE-120-STRCPY": {"name": "Unsafe C string copy", "cwe": "CWE-120/CWE-787", "shortDescription": "Unsafe C string copy may overflow the destination buffer.", "help": "Use std::string, strncpy_s on Windows, or copy with explicit bounds and NUL termination."},
    "DEMO-CWE-20-SCANF-RETURN": {"name": "Unchecked scanf result", "cwe": "CWE-20/CWE-252", "shortDescription": "scanf return value is ignored.", "help": "Check scanf's return value and reject invalid input."},
    "DEMO-CWE-787-INPUT-BOUND": {"name": "Unvalidated input used as array bound/index limit", "cwe": "CWE-20/CWE-787", "shortDescription": "User-controlled numeric input is used as an array bound.", "help": "Validate the input range before it controls array access."},
    "DEMO-CWE-330-RAND": {"name": "Weak random number generator", "cwe": "CWE-330", "shortDescription": "rand() is predictable.", "help": "Use a CSPRNG for security; if this is only simulation data, document that it is non-security randomness."},
    "DEMO-CWE-362-THREAD": {"name": "Thread lifecycle / race-prone Windows API use", "cwe": "CWE-362/CWE-667", "shortDescription": "TerminateThread/SuspendThread can leave shared state inconsistent.", "help": "Prefer cooperative cancellation, joins, condition variables, and scoped locks."},
    "DEMO-CWE-398-BUILD-BUG": {"name": "Likely build or logic typo", "cwe": "CWE-398", "shortDescription": "Suspicious typo or case mismatch.", "help": "Fix the typo and add CI compilation checks."},
    "DEMO-CWE-78-JAVA-EXEC": {"name": "Java command execution sink", "cwe": "CWE-78", "shortDescription": "Runtime.exec/ProcessBuilder may execute user-controlled commands.", "help": "Avoid shell command construction; use allow-lists and pass fixed argv arrays."},
    "DEMO-CWE-89-JAVA-SQL-CONCAT": {"name": "Java SQL query built by concatenation", "cwe": "CWE-89", "shortDescription": "Dynamic SQL strings may allow SQL injection.", "help": "Use PreparedStatement with bind parameters instead of string concatenation."},
    "DEMO-CWE-502-JAVA-DESERIALIZATION": {"name": "Java native deserialization", "cwe": "CWE-502", "shortDescription": "ObjectInputStream/readObject may deserialize attacker-controlled objects.", "help": "Avoid native Java deserialization for untrusted data; use safe formats and object filters."},
    "DEMO-CWE-327-JAVA-WEAK-CRYPTO": {"name": "Java weak cryptographic algorithm", "cwe": "CWE-327/CWE-328", "shortDescription": "MD5/SHA-1 are weak for integrity or password/security use.", "help": "Use modern algorithms such as SHA-256/HMAC-SHA-256, bcrypt, scrypt, or Argon2 as appropriate."},
    "DEMO-CWE-330-JAVA-RANDOM": {"name": "Java predictable random number generator", "cwe": "CWE-338/CWE-330", "shortDescription": "java.util.Random/Math.random are predictable.", "help": "Use java.security.SecureRandom for secrets, session IDs, reset tokens, and nonces."},
    "DEMO-CWE-22-JAVA-PATH": {"name": "Java path traversal candidate", "cwe": "CWE-22", "shortDescription": "User-controlled input appears to influence a file path.", "help": "Canonicalize paths, enforce a safe base directory, and reject traversal sequences."},
    "DEMO-CWE-78-PY-SHELL": {"name": "Python command execution sink", "cwe": "CWE-78", "shortDescription": "os.system/subprocess with shell=True can execute user-controlled commands.", "help": "Avoid shell=True; pass fixed argument lists and validate user-controlled values."},
    "DEMO-CWE-94-PY-EVAL": {"name": "Python dynamic code execution", "cwe": "CWE-94/CWE-95", "shortDescription": "eval/exec executes code represented as data.", "help": "Use safe parsers such as json.loads or ast.literal_eval, and never evaluate untrusted input."},
    "DEMO-CWE-502-PY-DESERIALIZATION": {"name": "Python unsafe deserialization", "cwe": "CWE-502", "shortDescription": "pickle/marshal/yaml.load can deserialize unsafe objects.", "help": "Avoid pickle/marshal for untrusted data; use yaml.safe_load or a strict JSON schema."},
    "DEMO-CWE-89-PY-SQL-DYNAMIC": {"name": "Python dynamic SQL execution", "cwe": "CWE-89", "shortDescription": "SQL passed to execute() is dynamically constructed.", "help": "Use parameterized queries instead of f-strings, %, format(), or string concatenation."},
    "DEMO-CWE-327-PY-WEAK-HASH": {"name": "Python weak cryptographic hash", "cwe": "CWE-327/CWE-328", "shortDescription": "MD5/SHA-1 are weak for security-sensitive hashing.", "help": "Use SHA-256/HMAC or a password hashing scheme such as bcrypt/scrypt/Argon2 as appropriate."},
    "DEMO-CWE-338-PY-RANDOM": {"name": "Python predictable random generator", "cwe": "CWE-338/CWE-330", "shortDescription": "random module output is predictable for secrets.", "help": "Use secrets.token_urlsafe/token_bytes or os.urandom for security-sensitive randomness."},
    "DEMO-CWE-295-PY-VERIFY-FALSE": {"name": "Python TLS certificate verification disabled", "cwe": "CWE-295", "shortDescription": "verify=False disables TLS certificate validation.", "help": "Remove verify=False and install/trust the proper CA certificate instead."},
    "DEMO-CWE-489-PY-DEBUG": {"name": "Python debug mode enabled", "cwe": "CWE-489/CWE-215", "shortDescription": "Debug mode can leak sensitive internals.", "help": "Disable debug mode outside local development."},
    "DEMO-CWE-798-HARDCODED-SECRET": {"name": "Hard-coded secret candidate", "cwe": "CWE-798/CWE-259", "shortDescription": "A password/token/key-like variable is assigned a string literal.", "help": "Move secrets to a secret manager or CI secret, and rotate exposed credentials."},
    "DEMO-CWE-20-SYNTAX-PARSE": {"name": "Source parse warning", "cwe": "CWE-20", "shortDescription": "The analyzer could not fully parse a source file.", "help": "Fix syntax errors so static analysis tools can reason about the file accurately."},
}

@dataclasses.dataclass(frozen=True)
class Finding:
    rule_id: str
    cwe: str
    severity: str
    language: str
    file: str
    line: int
    message: str
    evidence: str
    recommendation: str


def read_fact_rows(facts_dir: Path, name: str) -> list[list[str]]:
    path = facts_dir / f"{name}.facts"
    if not path.exists():
        return []
    rows: list[list[str]] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh, delimiter="\t"):
            if row:
                rows.append(row)
    return rows


def write_finding_csv(rows: list[list[Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        for row in rows:
            writer.writerow([str(x).replace("\t", " ").replace("\n", " ") for x in row])


def fallback_infer(facts_dir: Path, out_csv: Path) -> list[list[Any]]:
    """Python fallback mirroring rules/cwe_rules.dl for environments without Souffle."""
    rows: list[list[Any]] = []
    def emit(file: str, line: str | int, language: str, cwe: str, rule: str, severity: str, message: str, evidence: str, rec: str) -> None:
        rows.append([file, int(line), language, cwe, rule, severity, message, evidence, rec])

    for file, line, language, var, api, evidence in read_fact_rows(facts_dir, "unbounded_read"):
        emit(file, line, language, "CWE-120/CWE-787", "DEMO-CWE-120-CIN-CHAR-ARRAY", "error", f"Unbounded {api} read into fixed char buffer: {var}", evidence, RULES["DEMO-CWE-120-CIN-CHAR-ARRAY"]["help"])

    for row in read_fact_rows(facts_dir, "unsafe_call"):
        if len(row) < 6:
            continue
        file, line, language, api, cwe, evidence = row[:6]
        if cwe == "CWE-120/CWE-787" and api in {"strcpy", "strcat", "sprintf", "gets"}:
            emit(file, line, language, cwe, "DEMO-CWE-120-STRCPY", "error", f"{api} can overflow a destination buffer because it does not know the destination capacity.", evidence, RULES["DEMO-CWE-120-STRCPY"]["help"])
        elif api == "scanf-unchecked-return":
            emit(file, line, language, cwe, "DEMO-CWE-20-SCANF-RETURN", "warning", "scanf return value is ignored, so invalid input may leave the destination variable unchanged.", evidence, RULES["DEMO-CWE-20-SCANF-RETURN"]["help"])
        elif api == "rand":
            emit(file, line, language, cwe, "DEMO-CWE-330-RAND", "note", "rand() is predictable and is not suitable for security-sensitive randomness.", evidence, RULES["DEMO-CWE-330-RAND"]["help"])
        elif cwe == "CWE-362/CWE-667":
            emit(file, line, language, cwe, "DEMO-CWE-362-THREAD", "warning", f"{api} can leave shared state inconsistent and is race-prone.", evidence, RULES["DEMO-CWE-362-THREAD"]["help"])
        elif language == "Java" and cwe == "CWE-502":
            emit(file, line, language, cwe, "DEMO-CWE-502-JAVA-DESERIALIZATION", "warning", "ObjectInputStream/readObject may deserialize attacker-controlled objects.", evidence, RULES["DEMO-CWE-502-JAVA-DESERIALIZATION"]["help"])
        elif language == "Java" and cwe == "CWE-338/CWE-330":
            emit(file, line, language, cwe, "DEMO-CWE-330-JAVA-RANDOM", "warning", "java.util.Random/Math.random are predictable for security-sensitive tokens.", evidence, RULES["DEMO-CWE-330-JAVA-RANDOM"]["help"])
        elif language == "Python" and cwe == "CWE-94/CWE-95":
            emit(file, line, language, cwe, "DEMO-CWE-94-PY-EVAL", "error", "eval/exec/compile executes code represented as data.", evidence, RULES["DEMO-CWE-94-PY-EVAL"]["help"])
        elif language == "Python" and cwe == "CWE-502":
            emit(file, line, language, cwe, "DEMO-CWE-502-PY-DESERIALIZATION", "warning", "pickle/marshal/yaml.load can deserialize or construct unsafe objects.", evidence, RULES["DEMO-CWE-502-PY-DESERIALIZATION"]["help"])
        elif language == "Python" and cwe == "CWE-338/CWE-330":
            emit(file, line, language, cwe, "DEMO-CWE-338-PY-RANDOM", "warning", "Python random module output is predictable for security-sensitive secrets.", evidence, RULES["DEMO-CWE-338-PY-RANDOM"]["help"])
        elif language == "Python" and cwe == "CWE-295":
            emit(file, line, language, cwe, "DEMO-CWE-295-PY-VERIFY-FALSE", "warning", "verify=False disables TLS certificate validation.", evidence, RULES["DEMO-CWE-295-PY-VERIFY-FALSE"]["help"])
        elif language == "Python" and cwe == "CWE-489/CWE-215":
            emit(file, line, language, cwe, "DEMO-CWE-489-PY-DEBUG", "warning", "Debug mode can leak sensitive internals in production.", evidence, RULES["DEMO-CWE-489-PY-DEBUG"]["help"])

    for file, line, language, var, array, cap, evidence in read_fact_rows(facts_dir, "var_as_bound"):
        emit(file, line, language, "CWE-20/CWE-787", "DEMO-CWE-787-INPUT-BOUND", "error", f"User-controlled value {var} controls access to fixed array {array} with capacity {cap}.", evidence, RULES["DEMO-CWE-787-INPUT-BOUND"]["help"])

    for file, line, language, sink, cwe, kind, evidence in read_fact_rows(facts_dir, "tainted_sink"):
        if language == "Java" and cwe == "CWE-78":
            emit(file, line, language, cwe, "DEMO-CWE-78-JAVA-EXEC", "error", "Java command execution sink may execute user-controlled commands.", evidence, RULES["DEMO-CWE-78-JAVA-EXEC"]["help"])
        elif language == "Java" and cwe == "CWE-89":
            emit(file, line, language, cwe, "DEMO-CWE-89-JAVA-SQL-CONCAT", "error", "Java SQL string is dynamically constructed and may allow SQL injection.", evidence, RULES["DEMO-CWE-89-JAVA-SQL-CONCAT"]["help"])
        elif language == "Java" and cwe == "CWE-22":
            emit(file, line, language, cwe, "DEMO-CWE-22-JAVA-PATH", "warning", "User-controlled input appears to influence a file path.", evidence, RULES["DEMO-CWE-22-JAVA-PATH"]["help"])
        elif language == "Python" and cwe == "CWE-78":
            emit(file, line, language, cwe, "DEMO-CWE-78-PY-SHELL", "error", "Python command execution sink can execute user-controlled commands.", evidence, RULES["DEMO-CWE-78-PY-SHELL"]["help"])
        elif language == "Python" and cwe == "CWE-89":
            emit(file, line, language, cwe, "DEMO-CWE-89-PY-SQL-DYNAMIC", "error", "SQL passed to execute() is dynamically constructed.", evidence, RULES["DEMO-CWE-89-PY-SQL-DYNAMIC"]["help"])

    for file, line, language, algorithm, evidence in read_fact_rows(facts_dir, "weak_crypto"):
        if language == "Java":
            emit(file, line, language, "CWE-327/CWE-328", "DEMO-CWE-327-JAVA-WEAK-CRYPTO", "warning", f"Java weak cryptographic algorithm: {algorithm}", evidence, RULES["DEMO-CWE-327-JAVA-WEAK-CRYPTO"]["help"])
        elif language == "Python":
            emit(file, line, language, "CWE-327/CWE-328", "DEMO-CWE-327-PY-WEAK-HASH", "warning", f"Python weak cryptographic algorithm: {algorithm}", evidence, RULES["DEMO-CWE-327-PY-WEAK-HASH"]["help"])

    for file, line, language, name, evidence in read_fact_rows(facts_dir, "hardcoded_secret"):
        emit(file, line, language, "CWE-798/CWE-259", "DEMO-CWE-798-HARDCODED-SECRET", "warning", f"{language} hard-coded secret-like variable: {name}", evidence, RULES["DEMO-CWE-798-HARDCODED-SECRET"]["help"])

    for file, line, language, message, evidence in read_fact_rows(facts_dir, "syntax_warning"):
        if language == "Python":
            emit(file, line, language, "CWE-20", "DEMO-CWE-20-SYNTAX-PARSE", "warning", message, evidence, RULES["DEMO-CWE-20-SYNTAX-PARSE"]["help"])
        else:
            emit(file, line, language, "CWE-398", "DEMO-CWE-398-BUILD-BUG", "note", message, evidence, RULES["DEMO-CWE-398-BUILD-BUG"]["help"])

    # Deduplicate exact finding rows.
    unique: list[list[Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in sorted(rows, key=lambda r: (str(r[0]), int(r[1]), str(r[4]), str(r[6]))):
        key = tuple(row)
        if key not in seen:
            seen.add(key)
            unique.append(row)
    write_finding_csv(unique, out_csv)
    return unique


def read_findings_csv(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    findings: list[Finding] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        for row in reader:
            if len(row) < len(FINDING_COLUMNS):
                continue
            record = dict(zip(FINDING_COLUMNS, row[: len(FINDING_COLUMNS)]))
            try:
                line = int(record["line"])
            except ValueError:
                line = 1
            findings.append(Finding(
                rule_id=record["rule_id"],
                cwe=record["cwe"],
                severity=record["severity"],
                language=record["language"],
                file=record["file"],
                line=line,
                message=record["message"],
                evidence=record["evidence"],
                recommendation=record["recommendation"],
            ))
    # Deduplicate if Souffle emitted repeated rows through overlapping rules.
    result: list[Finding] = []
    seen: set[tuple[str, str, int, str, str]] = set()
    for f in sorted(findings, key=lambda x: (x.file, x.line, x.rule_id, x.message)):
        key = (f.rule_id, f.file, f.line, f.cwe, f.message)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def make_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules = []
    for rid, meta in sorted(RULES.items()):
        rules.append({
            "id": rid,
            "name": meta["name"],
            "shortDescription": {"text": meta["shortDescription"]},
            "fullDescription": {"text": f"Maps to {meta['cwe']}."},
            "help": {"text": meta["help"]},
            "properties": {"tags": ["security", meta["cwe"], "souffle-inferred"]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": "error" if f.severity == "error" else ("note" if f.severity == "note" else "warning"),
            "message": {"text": f"{f.cwe}: {f.message} Recommendation: {f.recommendation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": max(1, f.line)}}}],
            "properties": {"language": f.language, "cwe": f.cwe, "inference": "souffle-datalog-or-fallback"},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "coursework-cwe-souffle-analyzer", "informationUri": "https://cwe.mitre.org/", "rules": rules}}, "results": results}]}


def markdown_report(findings: list[Finding], inference_engine: str) -> str:
    by_lang: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    for f in findings:
        by_lang[f.language] = by_lang.get(f.language, 0) + 1
        by_cwe[f.cwe] = by_cwe.get(f.cwe, 0) + 1

    lines = ["# CWE 静态分析报告", "", f"共发现 **{len(findings)}** 个告警。", "", f"推理后端：`{inference_engine}`", ""]
    if findings:
        lines.extend(["## 汇总", "", "### 按语言", ""])
        for lang, count in sorted(by_lang.items()):
            lines.append(f"- {lang}: {count}")
        lines.extend(["", "### 按 CWE", ""])
        for cwe, count in sorted(by_cwe.items()):
            lines.append(f"- {cwe}: {count}")
        lines.append("")

    lines.extend([
        "## 分析架构",
        "",
        "本报告由 `extract_facts.py` 先从 C/C++、Java、Python 源码抽取 facts，再由 `rules/cwe_rules.dl` 的 Datalog 规则推导 CWE findings；若本机未安装 Soufflé，则使用与 Datalog 规则等价的 Python fallback 生成同形 `finding.csv`，保证课堂演示稳定。",
        "",
    ])

    for f in findings:
        lines.extend([
            f"## {f.cwe} · {f.file}:{f.line}",
            "",
            f"- 语言：`{f.language}`",
            f"- 规则：`{f.rule_id}`",
            f"- 严重性：`{f.severity}`",
            f"- 说明：{f.message}",
            f"- 证据：`{f.evidence}`",
            f"- 建议：{f.recommendation}",
            "",
        ])
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert Souffle finding.csv into reports/SARIF")
    ap.add_argument("--facts", default="analysis/facts", help="Facts directory for Python fallback inference")
    ap.add_argument("--datalog", default="analysis/datalog/finding.csv", help="Souffle finding.csv path")
    ap.add_argument("--json", default="analysis/findings.json")
    ap.add_argument("--markdown", default="analysis/report.md")
    ap.add_argument("--sarif", default="analysis/custom-cwe.sarif")
    ap.add_argument("--fallback", action="store_true", help="Generate finding.csv with Python fallback before conversion")
    ap.add_argument("--engine", default="souffle")
    args = ap.parse_args()

    datalog = Path(args.datalog)
    if args.fallback or not datalog.exists():
        fallback_infer(Path(args.facts), datalog)
        engine = "python-fallback-equivalent-to-souffle-rules"
    else:
        engine = args.engine

    findings = read_findings_csv(datalog)
    out_json = Path(args.json)
    out_md = Path(args.markdown)
    out_sarif = Path(args.sarif)
    for p in (out_json, out_md, out_sarif):
        p.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps([dataclasses.asdict(f) for f in findings], ensure_ascii=False, indent=2), encoding="utf-8")
    out_md.write_text(markdown_report(findings, engine), encoding="utf-8")
    out_sarif.write_text(json.dumps(make_sarif(findings), ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Wrote {len(findings)} findings")
    print(f"- {out_json}")
    print(f"- {out_md}")
    print(f"- {out_sarif}")
    print(f"- {datalog}")
    return 1 if any(f.severity == "error" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
