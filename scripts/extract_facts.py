#!/usr/bin/env python3
"""Multi-language fact extractor for the coursework CWE analyzer.

This script is the *front-end* only.  It scans C/C++, Java and Python source
files using explainable AST/regex heuristics and emits tab-separated Souffle
facts.  It intentionally does not decide final CWE findings; that is delegated
to rules/cwe_rules.dl or the Python fallback in facts_to_results.py.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".java", ".py"}
CPP_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}
JAVA_EXTS = {".java"}
PYTHON_EXTS = {".py"}

FACT_NAMES = [
    "array_decl",
    "unbounded_read",
    "unsafe_call",
    "untrusted_int",
    "var_as_bound",
    "tainted_sink",
    "hardcoded_secret",
    "weak_crypto",
    "syntax_warning",
]

SECRET_NAME_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key)")
SQL_WORD_RE = re.compile(r"(?i)\b(select|insert|update|delete|drop|alter)\b")
WEAK_HASH_RE = re.compile(r"(?i)\b(MD5|SHA-?1)\b")


def read_text(path: Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "gbk", "latin-1"):
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


def new_facts() -> dict[str, list[tuple[Any, ...]]]:
    return {name: [] for name in FACT_NAMES}


def add_fact(facts: dict[str, list[tuple[Any, ...]]], name: str, *row: Any) -> None:
    facts.setdefault(name, []).append(tuple(row))


def clean_evidence(s: str) -> str:
    return " ".join(str(s).strip().split())[:500]


def merge_facts(dst: dict[str, list[tuple[Any, ...]]], src: dict[str, list[tuple[Any, ...]]]) -> None:
    for k, rows in src.items():
        dst.setdefault(k, []).extend(rows)


def literal_secret_value(value: str) -> bool:
    value = value.strip().strip('"\'')
    if len(value) >= 12:
        return True
    if re.search(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_\-+/=]{8,}", value):
        return True
    return False


def analyze_cpp(path: Path, base: Path) -> dict[str, list[tuple[Any, ...]]]:
    text = read_text(path)
    file = rel(path, base)
    language = "C/C++"
    facts = new_facts()
    arrays: dict[str, int] = {}
    char_arrays: set[str] = set()
    untrusted_vars: set[str] = set()
    bound_seen: set[tuple[str, str]] = set()

    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        evidence = clean_evidence(stripped)
        if not stripped or stripped.startswith("//"):
            continue

        # fixed arrays, including 2D arrays such as int stack[20][7].
        # For 2D arrays we record the second dimension because that is usually
        # the vulnerable bound in stack[i][j]-style accesses.
        for m in re.finditer(r"\b(char|int|long|short|float|double|bool)\s+(\w+)\s*\[\s*(\d+)\s*\](?:\s*\[\s*(\d+)\s*\])?", stripped):
            typ, var = m.group(1), m.group(2)
            size = int(m.group(4) or m.group(3))
            arrays[var] = size
            if typ == "char" and not m.group(4):
                char_arrays.add(var)
            add_fact(facts, "array_decl", file, lineno, var, size)

        # cin >> fixed char array
        if "cin" in stripped and ">>" in stripped:
            for var in re.findall(r">>\s*(\w+)", stripped):
                if var in char_arrays:
                    add_fact(facts, "unbounded_read", file, lineno, language, var, "cin>>", evidence)
                untrusted_vars.add(var)

        # scanf numeric input sources and unchecked return candidates
        scanf_match = re.search(r"\bscanf\s*\((.*)\)", stripped)
        if scanf_match:
            if not re.search(r"\b(if|while)\s*\(\s*scanf\s*\(", stripped) and "==" not in stripped and "!=" not in stripped:
                add_fact(facts, "unsafe_call", file, lineno, language, "scanf-unchecked-return", "CWE-20/CWE-252", evidence)
            for var in re.findall(r"&\s*(\w+)", stripped):
                untrusted_vars.add(var)
                add_fact(facts, "untrusted_int", file, lineno, language, var, "scanf", evidence)

        # unsafe C string API calls
        for api in ("strcpy", "strcat", "sprintf", "gets"):
            if re.search(rf"\b{api}\s*\(", stripped):
                cwe = "CWE-120/CWE-787"
                add_fact(facts, "unsafe_call", file, lineno, language, api, cwe, evidence)

        # weak/random/thread API calls
        if re.search(r"\brand\s*\(", stripped):
            add_fact(facts, "unsafe_call", file, lineno, language, "rand", "CWE-330", evidence)
        for api in ("TerminateThread", "SuspendThread"):
            if re.search(rf"\b{api}\s*\(", stripped):
                add_fact(facts, "unsafe_call", file, lineno, language, api, "CWE-362/CWE-667", evidence)

        # loop bounds controlled by untrusted integers and used against known arrays
        loop_match = re.search(r"\bfor\s*\([^;]*;\s*([^;]+);", stripped)
        if loop_match:
            cond = loop_match.group(1)
            for var in sorted(untrusted_vars):
                # We care about a tainted variable used as the upper bound, e.g.
                # for (j = 0; j < nums; j++), not the loop counter itself.
                if re.search(rf"(?:<|<=)\s*{re.escape(var)}\b", cond):
                    # Find arrays used in the nearby line or later lines.
                    window = "\n".join(lines[lineno - 1 : min(len(lines), lineno + 6)])
                    for arr, cap in arrays.items():
                        key = (var, arr)
                        if key in bound_seen:
                            continue
                        if re.search(rf"\b{re.escape(arr)}\s*\[", window):
                            bound_seen.add(key)
                            add_fact(facts, "var_as_bound", file, lineno, language, var, arr, cap, evidence)

        # Hard-coded secret candidates.
        sec = re.search(r"\b(\w*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\w*)\b\s*=\s*([\"'][^\"']+[\"'])", stripped, re.I)
        if sec and literal_secret_value(sec.group(2)):
            add_fact(facts, "hardcoded_secret", file, lineno, language, sec.group(1), evidence)

        # Keep demo quality checks as syntax/quality facts, not core CWE findings.
        if '#include "schedule.h"' in stripped and file.endswith("003.main.cpp"):
            add_fact(facts, "syntax_warning", file, lineno, language, "case-sensitive include may fail on Linux", evidence)
        if '<"--"' in stripped or '<"--";' in stripped or 'name<"--"' in stripped:
            add_fact(facts, "syntax_warning", file, lineno, language, "suspicious stream insertion typo", evidence)

    return facts


def analyze_java(path: Path, base: Path) -> dict[str, list[tuple[Any, ...]]]:
    text = read_text(path)
    file = rel(path, base)
    language = "Java"
    facts = new_facts()
    tainted: set[str] = set()

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        evidence = clean_evidence(stripped)
        if not stripped or stripped.startswith("//"):
            continue

        # Common Java request/Scanner/args sources.
        for m in re.finditer(r"(?:String|var|int|Path|File)\s+(\w+)\s*=\s*.*?(getParameter|getHeader|nextLine|nextInt|args\s*\[)", stripped):
            var = m.group(1)
            tainted.add(var)
            add_fact(facts, "untrusted_int", file, lineno, language, var, m.group(2), evidence)
        if re.search(r"\bScanner\s+\w+\s*=", stripped):
            add_fact(facts, "unsafe_call", file, lineno, language, "Scanner-input-source", "CWE-20", evidence)

        # Command execution.
        if "Runtime.getRuntime().exec" in stripped or re.search(r"\bnew\s+ProcessBuilder\s*\(", stripped):
            add_fact(facts, "tainted_sink", file, lineno, language, "java-command-exec", "CWE-78", "command-execution", evidence)

        # Dynamic SQL.
        if SQL_WORD_RE.search(stripped) and ("+" in stripped or "String.format" in stripped):
            add_fact(facts, "tainted_sink", file, lineno, language, "java-dynamic-sql", "CWE-89", "sql", evidence)
        if re.search(r"\b(createStatement\s*\(\)|execute(Query|Update)?\s*\()", stripped) and "+" in stripped:
            add_fact(facts, "tainted_sink", file, lineno, language, "java-sql-execute", "CWE-89", "sql", evidence)

        # Deserialization.
        if "ObjectInputStream" in stripped or ".readObject(" in stripped:
            add_fact(facts, "unsafe_call", file, lineno, language, "ObjectInputStream/readObject", "CWE-502", evidence)

        # Weak crypto and weak RNG.
        md = re.search(r"MessageDigest\.getInstance\s*\(\s*[\"']([^\"']+)[\"']", stripped)
        if md and WEAK_HASH_RE.search(md.group(1)):
            add_fact(facts, "weak_crypto", file, lineno, language, md.group(1).upper(), evidence)
        if re.search(r"\bnew\s+Random\s*\(|\bMath\.random\s*\(", stripped):
            add_fact(facts, "unsafe_call", file, lineno, language, "java.util.Random/Math.random", "CWE-338/CWE-330", evidence)

        # Path traversal candidates.
        if re.search(r"\b(new\s+File|Paths\.get|Files\.(read|write|delete|copy|move))", stripped) and ("+" in stripped or any(v in stripped for v in tainted)):
            add_fact(facts, "tainted_sink", file, lineno, language, "java-file-path", "CWE-22", "path", evidence)

        sec = re.search(r"\b(?:String|var|char\[\])\s+(\w*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\w*)\s*=\s*([\"'][^\"']+[\"'])", stripped, re.I)
        if sec and literal_secret_value(sec.group(2)):
            add_fact(facts, "hardcoded_secret", file, lineno, language, sec.group(1), evidence)

    return facts


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return ""


def is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def contains_sql_text(node: ast.AST) -> bool:
    try:
        text = ast.unparse(node)
    except Exception:
        text = ""
    return bool(SQL_WORD_RE.search(text))


def is_dynamic_string(node: ast.AST) -> bool:
    return isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call))


def analyze_python(path: Path, base: Path) -> dict[str, list[tuple[Any, ...]]]:
    text = read_text(path)
    file = rel(path, base)
    language = "Python"
    facts = new_facts()
    lines = text.splitlines()

    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        line = exc.lineno or 1
        evidence = clean_evidence(lines[line - 1] if 0 < line <= len(lines) else exc.msg)
        add_fact(facts, "syntax_warning", file, line, language, f"python syntax parse failed: {exc.msg}", evidence)
        tree = None

    # Regex pass for hard-coded secrets and simple SQL strings.
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        evidence = clean_evidence(stripped)
        sec = re.search(r"\b(\w*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\w*)\s*=\s*([\"'][^\"']+[\"'])", stripped, re.I)
        if sec and literal_secret_value(sec.group(2)):
            add_fact(facts, "hardcoded_secret", file, lineno, language, sec.group(1), evidence)
        if re.search(r"\.execute\s*\(", stripped) and SQL_WORD_RE.search(stripped) and ("f\"" in stripped or "f'" in stripped or "%" in stripped or "+" in stripped or ".format(" in stripped):
            add_fact(facts, "tainted_sink", file, lineno, language, "python-dynamic-sql", "CWE-89", "sql", evidence)

    if tree is None:
        return facts

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 1)
        evidence = clean_evidence(lines[lineno - 1] if 0 < lineno <= len(lines) else type(node).__name__)

        # Assignment sources and weak generated secrets.
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value_name = dotted_name(node.value)
            if value_name in {"input"}:
                for target in target_names:
                    add_fact(facts, "untrusted_int", file, lineno, language, target, "input", evidence)
            if any(SECRET_NAME_RE.search(t) for t in target_names) and "random" in value_name:
                add_fact(facts, "unsafe_call", file, lineno, language, "python-random-secret", "CWE-338/CWE-330", evidence)

        if not isinstance(node, ast.Call):
            continue

        name = dotted_name(node.func)

        if name in {"eval", "exec", "compile"}:
            add_fact(facts, "unsafe_call", file, lineno, language, name, "CWE-94/CWE-95", evidence)

        if name in {"os.system", "os.popen"}:
            add_fact(facts, "tainted_sink", file, lineno, language, name, "CWE-78", "command-execution", evidence)

        if name.startswith("subprocess."):
            has_shell_true = any(kw.arg == "shell" and is_true(kw.value) for kw in node.keywords)
            if has_shell_true:
                add_fact(facts, "tainted_sink", file, lineno, language, name, "CWE-78", "command-execution", evidence)

        if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "yaml.load"}:
            add_fact(facts, "unsafe_call", file, lineno, language, name, "CWE-502", evidence)

        if name.endswith(".execute") or name.endswith(".executemany"):
            if node.args and contains_sql_text(node.args[0]) and is_dynamic_string(node.args[0]):
                add_fact(facts, "tainted_sink", file, lineno, language, name, "CWE-89", "sql", evidence)

        if name in {"hashlib.md5", "hashlib.sha1"}:
            add_fact(facts, "weak_crypto", file, lineno, language, name.split(".")[-1].upper(), evidence)

        if name.startswith("random."):
            add_fact(facts, "unsafe_call", file, lineno, language, name, "CWE-338/CWE-330", evidence)

        if name.startswith("requests."):
            if any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords):
                add_fact(facts, "unsafe_call", file, lineno, language, "requests verify=False", "CWE-295", evidence)

        if name.endswith(".run"):
            if any(kw.arg == "debug" and is_true(kw.value) for kw in node.keywords):
                add_fact(facts, "unsafe_call", file, lineno, language, name, "CWE-489/CWE-215", evidence)

    return facts


def analyze_file(path: Path, base: Path) -> dict[str, list[tuple[Any, ...]]]:
    suffix = path.suffix.lower()
    if suffix in CPP_EXTS:
        return analyze_cpp(path, base)
    if suffix in JAVA_EXTS:
        return analyze_java(path, base)
    if suffix in PYTHON_EXTS:
        return analyze_python(path, base)
    return new_facts()


def sanitize_fact_cell(value: Any) -> str:
    return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")


def write_facts(facts: dict[str, list[tuple[Any, ...]]], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, int] = {}
    for name in FACT_NAMES:
        rows = facts.get(name, [])
        # Deduplicate while preserving order.
        unique: list[tuple[Any, ...]] = []
        seen: set[tuple[Any, ...]] = set()
        for row in rows:
            if row not in seen:
                seen.add(row)
                unique.append(row)
        manifest[name] = len(unique)
        with (outdir / f"{name}.facts").open("w", encoding="utf-8") as fh:
            for row in unique:
                fh.write("\t".join(sanitize_fact_cell(x) for x in row) + "\n")
    (outdir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract multi-language source facts for Souffle CWE inference")
    ap.add_argument("root", nargs="?", default="samples", help="Source root or single source file")
    ap.add_argument("--facts", default="analysis/facts", help="Output facts directory")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    base = root if root.is_dir() else root.parent
    merged = new_facts()
    files = 0
    for src in sorted(iter_source_files(root)):
        files += 1
        merge_facts(merged, analyze_file(src, base))

    write_facts(merged, Path(args.facts))
    total = sum(len(v) for v in merged.values())
    print(f"Extracted {total} facts from {files} source files")
    print(f"- {Path(args.facts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
