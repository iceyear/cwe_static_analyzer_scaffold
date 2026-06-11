#!/usr/bin/env python3
"""A tiny multi-language CWE-oriented static analyzer for coursework demos.

The analyzer is intentionally conservative and explainable.  It extracts simple
facts from C/C++, Java, and Python source text, applies hand-written rules, and
emits JSON/Markdown/SARIF/facts that can be fed to Souffle for a formal Datalog
presentation.
"""
from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
]


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


RULES: Dict[str, Dict[str, str]] = {
    # C/C++ rules
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
        "help": "Validate the input range before it controls array access.",
    },
    "DEMO-CWE-330-RAND": {
        "name": "Weak random number generator",
        "cwe": "CWE-330",
        "shortDescription": "rand()/Random/random are predictable and not suitable for security-sensitive randomness.",
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
    # Java rules
    "DEMO-CWE-78-JAVA-EXEC": {
        "name": "Java command execution sink",
        "cwe": "CWE-78",
        "shortDescription": "Runtime.exec/ProcessBuilder may execute user-controlled commands.",
        "help": "Avoid shell command construction; use allow-lists and pass fixed argv arrays.",
    },
    "DEMO-CWE-89-JAVA-SQL-CONCAT": {
        "name": "Java SQL query built by concatenation",
        "cwe": "CWE-89",
        "shortDescription": "Dynamic SQL strings may allow SQL injection.",
        "help": "Use PreparedStatement with bind parameters instead of string concatenation.",
    },
    "DEMO-CWE-502-JAVA-DESERIALIZATION": {
        "name": "Java native deserialization",
        "cwe": "CWE-502",
        "shortDescription": "ObjectInputStream/readObject may deserialize attacker-controlled objects.",
        "help": "Avoid native Java deserialization for untrusted data; use safe formats and object filters.",
    },
    "DEMO-CWE-327-JAVA-WEAK-CRYPTO": {
        "name": "Java weak cryptographic algorithm",
        "cwe": "CWE-327/CWE-328",
        "shortDescription": "MD5/SHA-1 are weak for integrity or password/security use.",
        "help": "Use modern algorithms such as SHA-256/HMAC-SHA-256, bcrypt, scrypt, or Argon2 as appropriate.",
    },
    "DEMO-CWE-330-JAVA-RANDOM": {
        "name": "Java predictable random number generator",
        "cwe": "CWE-338/CWE-330",
        "shortDescription": "java.util.Random/Math.random are predictable for security-sensitive tokens.",
        "help": "Use java.security.SecureRandom for secrets, session IDs, reset tokens, and nonces.",
    },
    "DEMO-CWE-22-JAVA-PATH": {
        "name": "Java path traversal candidate",
        "cwe": "CWE-22",
        "shortDescription": "User-controlled input appears to influence a file path.",
        "help": "Canonicalize paths, enforce a safe base directory, and reject traversal sequences.",
    },
    # Python rules
    "DEMO-CWE-78-PY-SHELL": {
        "name": "Python command execution sink",
        "cwe": "CWE-78",
        "shortDescription": "os.system/subprocess with shell=True can execute user-controlled commands.",
        "help": "Avoid shell=True; pass fixed argument lists and validate user-controlled values.",
    },
    "DEMO-CWE-94-PY-EVAL": {
        "name": "Python dynamic code execution",
        "cwe": "CWE-94/CWE-95",
        "shortDescription": "eval/exec executes code represented as data.",
        "help": "Use safe parsers such as json.loads or ast.literal_eval, and never evaluate untrusted input.",
    },
    "DEMO-CWE-502-PY-DESERIALIZATION": {
        "name": "Python unsafe deserialization",
        "cwe": "CWE-502",
        "shortDescription": "pickle/marshal/yaml.load can deserialize or construct unsafe objects.",
        "help": "Avoid pickle/marshal for untrusted data; use yaml.safe_load or a strict JSON schema.",
    },
    "DEMO-CWE-89-PY-SQL-DYNAMIC": {
        "name": "Python dynamic SQL execution",
        "cwe": "CWE-89",
        "shortDescription": "SQL passed to execute() is dynamically constructed.",
        "help": "Use parameterized queries instead of f-strings, %, format(), or string concatenation.",
    },
    "DEMO-CWE-327-PY-WEAK-HASH": {
        "name": "Python weak cryptographic hash",
        "cwe": "CWE-327/CWE-328",
        "shortDescription": "MD5/SHA-1 are weak for security-sensitive hashing.",
        "help": "Use SHA-256/HMAC or a password hashing scheme such as bcrypt/scrypt/Argon2 as appropriate.",
    },
    "DEMO-CWE-338-PY-RANDOM": {
        "name": "Python predictable random generator",
        "cwe": "CWE-338/CWE-330",
        "shortDescription": "random module output is predictable for security-sensitive secrets.",
        "help": "Use secrets.token_urlsafe/token_bytes or os.urandom for security-sensitive randomness.",
    },
    "DEMO-CWE-295-PY-VERIFY-FALSE": {
        "name": "Python TLS certificate verification disabled",
        "cwe": "CWE-295",
        "shortDescription": "verify=False disables TLS certificate validation.",
        "help": "Remove verify=False and install/trust the proper CA certificate instead.",
    },
    "DEMO-CWE-489-PY-DEBUG": {
        "name": "Python debug mode enabled",
        "cwe": "CWE-489/CWE-215",
        "shortDescription": "Debug mode can leak sensitive internals in production.",
        "help": "Disable debug mode outside local development.",
    },
    # Generic multi-language rules
    "DEMO-CWE-798-HARDCODED-SECRET": {
        "name": "Hard-coded secret candidate",
        "cwe": "CWE-798/CWE-259",
        "shortDescription": "A password/token/key-like variable is assigned a string literal.",
        "help": "Move secrets to a secret manager or CI secret, and rotate exposed credentials.",
    },
    "DEMO-CWE-20-SYNTAX-PARSE": {
        "name": "Source parse warning",
        "cwe": "CWE-20",
        "shortDescription": "The analyzer could not fully parse a source file.",
        "help": "Fix syntax errors so static analysis tools can reason about the file accurately.",
    },
}


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


def new_facts() -> Dict[str, List[Tuple[Any, ...]]]:
    return {name: [] for name in FACT_NAMES}


def add(
    findings: List[Finding],
    rule_id: str,
    language: str,
    file: str,
    line: int,
    message: str,
    evidence: str,
    recommendation: Optional[str] = None,
    severity: str = "warning",
) -> None:
    findings.append(
        Finding(
            rule_id=rule_id,
            cwe=RULES[rule_id]["cwe"],
            severity=severity,
            language=language,
            file=file,
            line=max(1, int(line)),
            message=message,
            evidence=evidence.strip(),
            recommendation=recommendation or RULES[rule_id]["help"],
        )
    )


def source_line(lines: List[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def split_cin_targets(expr: str) -> List[str]:
    expr = expr.split(";", 1)[0]
    pieces = [x.strip() for x in expr.split(">>")]
    targets: List[str] = []
    for piece in pieces[1:]:
        m = re.match(r"([A-Za-z_]\w*)", piece)
        if m:
            targets.append(m.group(1))
    return targets


def analyze_cpp(path: Path, base: Path) -> Tuple[List[Finding], Dict[str, List[Tuple[Any, ...]]]]:
    text = read_text(path)
    lines = text.splitlines()
    file = rel(path, base)
    language = "C/C++"
    findings: List[Finding] = []
    facts = new_facts()

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
                        language,
                        file,
                        i,
                        f"`cin >> {target}` writes into fixed char[{char_arrays[target]}] without a width limit.",
                        stripped,
                        "Replace the buffer with std::string, or use std::setw(buffer_size) before extraction.",
                        "error",
                    )

        if re.search(r"\bstrcpy\s*\(", stripped):
            facts["unsafe_call"].append((file, i, "C/C++", "strcpy", "CWE-120"))
            add(
                findings,
                "DEMO-CWE-120-STRCPY",
                language,
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
                language,
                file,
                i,
                f"Return value of `scanf` is ignored when reading `{var}`.",
                stripped,
                "Require `scanf(...) == 1`; reject non-numeric input and initialize variables safely.",
            )

        if re.search(r"\brand\s*\(", stripped):
            facts["unsafe_call"].append((file, i, "C/C++", "rand", "CWE-330"))
            add(
                findings,
                "DEMO-CWE-330-RAND",
                language,
                file,
                i,
                "`rand()` is predictable; do not use it for security-sensitive randomness.",
                stripped,
                "For simulation this is acceptable if documented; otherwise use a CSPRNG.",
                "note",
            )

        for api in ("TerminateThread", "SuspendThread"):
            if re.search(rf"\b{api}\s*\(", stripped):
                facts["unsafe_call"].append((file, i, "C/C++", api, "CWE-362"))
                add(
                    findings,
                    "DEMO-CWE-362-THREAD",
                    language,
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
                language,
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
                language,
                file,
                i,
                "Linux/Arch is case-sensitive: source includes `schedule.h`, but sample file is `Schedule.h`.",
                stripped,
                "Rename the include or the file so GitHub Actions/Linux can compile it.",
                "warning",
            )

    for var, scanf_line in scanf_int_vars.items():
        range_check = re.compile(rf"\b{re.escape(var)}\b\s*(<=|<|>=|>)\s*\d+|\d+\s*(<=|<|>=|>)\s*\b{re.escape(var)}\b")
        has_nearby_range_check = any(range_check.search(x) and "printf" not in x for x in lines[max(0, scanf_line - 1): min(len(lines), scanf_line + 12)])
        for i, line in enumerate(lines, start=1):
            if re.search(rf"for\s*\([^;]*;[^;]*<\s*{re.escape(var)}\b", line):
                window = "\n".join(lines[i - 1:min(len(lines), i + 8)])
                for arr, dims in array_dims.items():
                    if re.search(rf"\b{re.escape(arr)}\s*\[[^\]]+\]\s*\[[^\]]+\]", window) or re.search(rf"\b{re.escape(arr)}\s*\[[^\]]+\]", window):
                        cap = dims[-1]
                        facts["var_as_bound"].append((file, i, var, arr, cap))
                        facts["tainted_sink"].append((file, i, language, arr, "CWE-20/CWE-787", "array-bound"))
                        if not has_nearby_range_check:
                            add(
                                findings,
                                "DEMO-CWE-787-INPUT-BOUND",
                                language,
                                file,
                                i,
                                f"Input variable `{var}` controls a loop that indexes fixed array `{arr}` with capacity {cap}.",
                                line.strip(),
                                f"Validate `{var}` before the loop, e.g. `if ({var} < 1 || {var} > {cap}) return;`.",
                                "error",
                            )
                        break

    return findings, facts


def analyze_java(path: Path, base: Path) -> Tuple[List[Finding], Dict[str, List[Tuple[Any, ...]]]]:
    text = read_text(path)
    lines = text.splitlines()
    file = rel(path, base)
    language = "Java"
    findings: List[Finding] = []
    facts = new_facts()
    untrusted_vars: Dict[str, int] = {}
    sql_vars: Dict[str, int] = {}

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        secret = re.search(r'\b(?:String|char\s*\[\]|byte\s*\[\]|var)\s+([A-Za-z_]\w*)\s*=\s*"([^"]{4,})"', stripped)
        if secret and SECRET_NAME_RE.search(secret.group(1)):
            facts["hardcoded_secret"].append((file, i, language, secret.group(1)))
            facts["unsafe_call"].append((file, i, language, "hardcoded-secret", "CWE-798"))
            add(
                findings,
                "DEMO-CWE-798-HARDCODED-SECRET",
                language,
                file,
                i,
                f"Secret-like Java variable `{secret.group(1)}` is assigned a string literal.",
                stripped,
                severity="warning",
            )

        assign_param = re.search(r'\b(?:String|var)?\s*([A-Za-z_]\w*)\s*=\s*[^;]*\b(?:getParameter|getHeader|getQueryString|nextLine|next)\s*\(', stripped)
        if assign_param:
            untrusted_vars[assign_param.group(1)] = i

        sql_assign = re.search(r'\b(?:String|var)\s+([A-Za-z_]\w*)\s*=\s*(.+);', stripped)
        if sql_assign and SQL_WORD_RE.search(sql_assign.group(2)) and ("+" in sql_assign.group(2) or any(v in sql_assign.group(2) for v in untrusted_vars)):
            sql_vars[sql_assign.group(1)] = i
            facts["tainted_sink"].append((file, i, language, sql_assign.group(1), "CWE-89", "sql-construction"))
            add(
                findings,
                "DEMO-CWE-89-JAVA-SQL-CONCAT",
                language,
                file,
                i,
                f"SQL string `{sql_assign.group(1)}` is built dynamically and may include untrusted input.",
                stripped,
                severity="error",
            )

        if re.search(r'\b(?:execute|executeQuery|executeUpdate)\s*\(', stripped):
            dynamic_sql = "+" in stripped or any(re.search(rf"\b{re.escape(v)}\b", stripped) for v in sql_vars) or any(re.search(rf"\b{re.escape(v)}\b", stripped) for v in untrusted_vars)
            if dynamic_sql:
                facts["tainted_sink"].append((file, i, language, "execute", "CWE-89", "sql-execute"))
                add(
                    findings,
                    "DEMO-CWE-89-JAVA-SQL-CONCAT",
                    language,
                    file,
                    i,
                    "Dynamic SQL is passed to a JDBC execute method.",
                    stripped,
                    severity="error",
                )

        if "Runtime.getRuntime().exec" in stripped or re.search(r"\bnew\s+ProcessBuilder\s*\(", stripped):
            sink = "Runtime.exec" if "Runtime.getRuntime().exec" in stripped else "ProcessBuilder"
            facts["tainted_sink"].append((file, i, language, sink, "CWE-78", "command"))
            facts["unsafe_call"].append((file, i, language, sink, "CWE-78"))
            add(
                findings,
                "DEMO-CWE-78-JAVA-EXEC",
                language,
                file,
                i,
                f"`{sink}` executes an OS command; dynamic arguments may become command injection.",
                stripped,
                severity="error" if any(v in stripped for v in untrusted_vars) or "+" in stripped else "warning",
            )

        if re.search(r"\bnew\s+ObjectInputStream\s*\(", stripped) or re.search(r"\.readObject\s*\(", stripped):
            facts["tainted_sink"].append((file, i, language, "ObjectInputStream/readObject", "CWE-502", "deserialization"))
            facts["unsafe_call"].append((file, i, language, "ObjectInputStream/readObject", "CWE-502"))
            add(
                findings,
                "DEMO-CWE-502-JAVA-DESERIALIZATION",
                language,
                file,
                i,
                "Native Java deserialization appears in the code.",
                stripped,
                severity="warning",
            )

        weak = re.search(r'MessageDigest\.getInstance\s*\(\s*"([^"]+)"', stripped)
        if weak and WEAK_HASH_RE.search(weak.group(1)):
            facts["weak_crypto"].append((file, i, language, weak.group(1)))
            facts["unsafe_call"].append((file, i, language, f"MessageDigest:{weak.group(1)}", "CWE-327"))
            add(
                findings,
                "DEMO-CWE-327-JAVA-WEAK-CRYPTO",
                language,
                file,
                i,
                f"Weak digest algorithm `{weak.group(1)}` is requested.",
                stripped,
            )

        if re.search(r"\bnew\s+Random\s*\(", stripped) or re.search(r"\bMath\.random\s*\(", stripped):
            facts["unsafe_call"].append((file, i, language, "Random/Math.random", "CWE-338"))
            add(
                findings,
                "DEMO-CWE-330-JAVA-RANDOM",
                language,
                file,
                i,
                "Predictable Java random generator is used.",
                stripped,
                severity="note",
            )

        if re.search(r"\bnew\s+(?:File|FileInputStream|FileReader|Path)\s*\(", stripped) and any(v in stripped for v in untrusted_vars):
            facts["tainted_sink"].append((file, i, language, "file-path", "CWE-22", "path"))
            add(
                findings,
                "DEMO-CWE-22-JAVA-PATH",
                language,
                file,
                i,
                "User-controlled input appears to influence a file path.",
                stripped,
                severity="warning",
            )

    return findings, facts


def full_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = full_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return full_name(node.func)
    return ""


def is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def literal_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def string_fragments(node: ast.AST) -> List[str]:
    out: List[str] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        out.append(node.value)
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            out.extend(string_fragments(value))
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        out.extend(string_fragments(node.left))
        out.extend(string_fragments(node.right))
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        out.extend(string_fragments(node.func.value))
    return out


def is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    if isinstance(node, ast.Name):
        return True
    return False


def analyze_python(path: Path, base: Path) -> Tuple[List[Finding], Dict[str, List[Tuple[Any, ...]]]]:
    text = read_text(path)
    lines = text.splitlines()
    file = rel(path, base)
    language = "Python"
    findings: List[Finding] = []
    facts = new_facts()

    try:
        tree = ast.parse(text, filename=file)
    except SyntaxError as exc:
        add(
            findings,
            "DEMO-CWE-20-SYNTAX-PARSE",
            language,
            file,
            exc.lineno or 1,
            f"Python parser failed: {exc.msg}.",
            source_line(lines, exc.lineno or 1),
            "Fix syntax errors so AST-based security checks can run.",
            "warning",
        )
        return findings, facts

    tainted_vars: Dict[str, int] = {}
    sql_vars: Dict[str, int] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value_name = full_name(node.value)
            if value_name in {"input", "flask.request.args.get", "flask.request.form.get", "request.args.get", "request.form.get", "request.GET.get", "request.POST.get"}:
                for t in targets:
                    tainted_vars[t] = node.lineno
            for target in targets:
                val = literal_string(node.value)
                if val and len(val) >= 4 and SECRET_NAME_RE.search(target):
                    facts["hardcoded_secret"].append((file, node.lineno, language, target))
                    facts["unsafe_call"].append((file, node.lineno, language, "hardcoded-secret", "CWE-798"))
                    add(
                        findings,
                        "DEMO-CWE-798-HARDCODED-SECRET",
                        language,
                        file,
                        node.lineno,
                        f"Secret-like Python variable `{target}` is assigned a string literal.",
                        source_line(lines, node.lineno),
                        severity="warning",
                    )
                if SQL_WORD_RE.search(" ".join(string_fragments(node.value))) and is_dynamic_string(node.value):
                    sql_vars[target] = node.lineno
                    facts["tainted_sink"].append((file, node.lineno, language, target, "CWE-89", "sql-construction"))

        if not isinstance(node, ast.Call):
            continue

        name = full_name(node.func)
        lineno = getattr(node, "lineno", 1)
        evidence = source_line(lines, lineno)

        shell_true = any(kw.arg == "shell" and is_true(kw.value) for kw in node.keywords)
        if name in {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"} or (name.startswith("subprocess.") and shell_true):
            facts["tainted_sink"].append((file, lineno, language, name, "CWE-78", "command"))
            facts["unsafe_call"].append((file, lineno, language, name, "CWE-78"))
            add(
                findings,
                "DEMO-CWE-78-PY-SHELL",
                language,
                file,
                lineno,
                f"Command execution sink `{name}` is used" + (" with `shell=True`." if shell_true else "."),
                evidence,
                severity="error",
            )

        if name in {"eval", "exec", "compile"}:
            facts["tainted_sink"].append((file, lineno, language, name, "CWE-94", "code-eval"))
            facts["unsafe_call"].append((file, lineno, language, name, "CWE-94"))
            add(
                findings,
                "DEMO-CWE-94-PY-EVAL",
                language,
                file,
                lineno,
                f"Dynamic code execution `{name}` appears in the code.",
                evidence,
                severity="error",
            )

        if name in {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "dill.load", "dill.loads"}:
            facts["tainted_sink"].append((file, lineno, language, name, "CWE-502", "deserialization"))
            facts["unsafe_call"].append((file, lineno, language, name, "CWE-502"))
            add(
                findings,
                "DEMO-CWE-502-PY-DESERIALIZATION",
                language,
                file,
                lineno,
                f"Unsafe Python deserialization sink `{name}` appears in the code.",
                evidence,
                severity="warning",
            )

        if name == "yaml.load":
            loader_names = {full_name(kw.value) for kw in node.keywords if kw.arg and kw.arg.lower() == "loader"}
            if not loader_names or any("SafeLoader" not in x for x in loader_names):
                facts["tainted_sink"].append((file, lineno, language, name, "CWE-502", "yaml-load"))
                facts["unsafe_call"].append((file, lineno, language, name, "CWE-502"))
                add(
                    findings,
                    "DEMO-CWE-502-PY-DESERIALIZATION",
                    language,
                    file,
                    lineno,
                    "`yaml.load` is used without an explicit SafeLoader.",
                    evidence,
                    "Use yaml.safe_load or Loader=yaml.SafeLoader.",
                    "warning",
                )

        if name.endswith(".execute") and node.args:
            first = node.args[0]
            sql_text = " ".join(string_fragments(first))
            dynamic = is_dynamic_string(first) or (isinstance(first, ast.Name) and first.id in sql_vars)
            if dynamic or SQL_WORD_RE.search(sql_text):
                if dynamic or SQL_WORD_RE.search(sql_text):
                    facts["tainted_sink"].append((file, lineno, language, name, "CWE-89", "sql-execute"))
                    add(
                        findings,
                        "DEMO-CWE-89-PY-SQL-DYNAMIC",
                        language,
                        file,
                        lineno,
                        "Potentially dynamic SQL is passed to execute().",
                        evidence,
                        severity="error" if dynamic else "warning",
                    )

        if name in {"hashlib.md5", "hashlib.sha1"}:
            alg = name.rsplit(".", 1)[-1].upper()
            facts["weak_crypto"].append((file, lineno, language, alg))
            facts["unsafe_call"].append((file, lineno, language, name, "CWE-327"))
            add(
                findings,
                "DEMO-CWE-327-PY-WEAK-HASH",
                language,
                file,
                lineno,
                f"Weak hash `{alg}` is used.",
                evidence,
                severity="warning",
            )

        if name.startswith("random.") or name == "random":
            facts["unsafe_call"].append((file, lineno, language, name, "CWE-338"))
            add(
                findings,
                "DEMO-CWE-338-PY-RANDOM",
                language,
                file,
                lineno,
                "Python `random` module is predictable if used for security tokens.",
                evidence,
                severity="note",
            )

        if name.startswith("requests."):
            if any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False for kw in node.keywords):
                facts["unsafe_call"].append((file, lineno, language, name, "CWE-295"))
                add(
                    findings,
                    "DEMO-CWE-295-PY-VERIFY-FALSE",
                    language,
                    file,
                    lineno,
                    "TLS certificate verification is disabled with `verify=False`.",
                    evidence,
                    severity="error",
                )

        if name.endswith(".run"):
            if any(kw.arg == "debug" and is_true(kw.value) for kw in node.keywords):
                facts["unsafe_call"].append((file, lineno, language, name, "CWE-489"))
                add(
                    findings,
                    "DEMO-CWE-489-PY-DEBUG",
                    language,
                    file,
                    lineno,
                    "Application run method enables debug mode.",
                    evidence,
                    severity="warning",
                )

    return findings, facts


def analyze_file(path: Path, base: Path) -> Tuple[List[Finding], Dict[str, List[Tuple[Any, ...]]]]:
    suffix = path.suffix.lower()
    if suffix in CPP_EXTS:
        return analyze_cpp(path, base)
    if suffix in JAVA_EXTS:
        return analyze_java(path, base)
    if suffix in PYTHON_EXTS:
        return analyze_python(path, base)
    return [], new_facts()


def make_sarif(findings: List[Finding]) -> dict:
    rules = []
    for rid, meta in sorted(RULES.items()):
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
            "properties": {"language": f.language, "cwe": f.cwe},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "coursework-cwe-static-analyzer", "informationUri": "https://cwe.mitre.org/", "rules": rules}},
            "results": results,
        }],
    }


def write_facts(facts: Dict[str, List[Tuple[Any, ...]]], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for name in FACT_NAMES:
        rows = facts.get(name, [])
        with (outdir / f"{name}.facts").open("w", encoding="utf-8") as f:
            for row in rows:
                f.write("\t".join(str(x).replace("\t", " ").replace("\n", " ") for x in row) + "\n")


def markdown_report(findings: List[Finding]) -> str:
    by_lang: Dict[str, int] = {}
    by_cwe: Dict[str, int] = {}
    for f in findings:
        by_lang[f.language] = by_lang.get(f.language, 0) + 1
        by_cwe[f.cwe] = by_cwe.get(f.cwe, 0) + 1

    lines = ["# CWE 静态分析报告", "", f"共发现 **{len(findings)}** 个告警。", ""]
    if findings:
        lines.extend(["## 汇总", ""])
        lines.append("### 按语言")
        lines.append("")
        for lang, count in sorted(by_lang.items()):
            lines.append(f"- {lang}: {count}")
        lines.append("")
        lines.append("### 按 CWE")
        lines.append("")
        for cwe, count in sorted(by_cwe.items()):
            lines.append(f"- {cwe}: {count}")
        lines.append("")

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
    merged_facts = new_facts()

    for src in sorted(iter_source_files(root)):
        findings, facts = analyze_file(src, base)
        all_findings.extend(findings)
        for k, rows in facts.items():
            merged_facts.setdefault(k, []).extend(rows)

    # De-duplicate noisy overlapping heuristic findings.
    seen = set()
    unique_findings: List[Finding] = []
    for f in sorted(all_findings, key=lambda x: (x.file, x.line, x.rule_id, x.message)):
        key = (f.rule_id, f.file, f.line, f.message)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    all_findings = unique_findings

    json_path = Path(args.json)
    md_path = Path(args.markdown)
    sarif_path = Path(args.sarif)
    for p in (json_path, md_path, sarif_path):
        p.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(json.dumps([dataclasses.asdict(f) for f in all_findings], ensure_ascii=False, indent=2), encoding="utf-8")
    sarif_path.write_text(json.dumps(make_sarif(all_findings), ensure_ascii=False, indent=2), encoding="utf-8")
    write_facts(merged_facts, Path(args.facts))
    md_path.write_text(markdown_report(all_findings), encoding="utf-8")

    print(f"Wrote {len(all_findings)} findings")
    print(f"- {json_path}")
    print(f"- {md_path}")
    print(f"- {sarif_path}")
    print(f"- {Path(args.facts)}")
    return 1 if any(f.severity == "error" for f in all_findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
