#!/usr/bin/env python3
"""Gemma/Gemini diff suggestion generator for classroom demos.

This script does NOT apply patches. It reads local analyzer findings, collects
small source snippets, asks Gemma/Gemini for unified-diff suggestions, and
renders them as GitHub Flavored Markdown for GitHub Actions job summaries.

Usage:
  python scripts/gemma_diff_suggest.py analysis/findings.json --src samples \
    --out-md analysis/repair/gemma_diff_suggestions.md \
    --out-json analysis/repair/gemma_diff_suggestions.json \
    --out-patch analysis/repair/suggested.patch

Environment:
  GEMINI_API_KEY        Google AI Studio API key. If absent, a pasteable prompt is written.
  GEMINI_MODEL          Defaults to gemma-4-31b-it.
  GEMINI_STRICT=1       Exit non-zero on API/parsing errors. Default is fail-open.
  GEMMA_PATCH_LIMIT     Max findings to send. Default: 6.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_MODEL = "gemma-4-31b-it"
API_BASE = "https://generativelanguage.googleapis.com/v1beta"

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "summary": {"type": "string"},
        "patches": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "cwe": {"type": "string"},
                    "title": {"type": "string"},
                    "risk": {"type": "string"},
                    "repair_strategy": {"type": "string"},
                    "unified_diff": {"type": "string"},
                    "review_notes": {"type": "array", "items": {"type": "string"}},
                },
                "required": [
                    "file",
                    "line",
                    "cwe",
                    "title",
                    "risk",
                    "repair_strategy",
                    "unified_diff",
                    "review_notes",
                ],
            },
        },
    },
    "required": ["title", "summary", "patches"],
}

SEVERITY_RANK = {"error": 0, "warning": 1, "note": 2, "info": 3}
PATCHABLE_KEYWORDS = (
    "CWE-78",
    "CWE-89",
    "CWE-94",
    "CWE-95",
    "CWE-120",
    "CWE-787",
    "CWE-327",
    "CWE-328",
    "CWE-338",
    "CWE-295",
    "CWE-489",
    "CWE-798",
    "CWE-502",
)


def load_findings(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        items = data.get("findings", [])
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
    return []


def pick_findings(findings: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    def patchable(f: dict[str, Any]) -> bool:
        cwe = str(f.get("cwe", ""))
        rule = str(f.get("rule_id", ""))
        return any(k in cwe or k in rule for k in PATCHABLE_KEYWORDS)

    chosen = [f for f in findings if patchable(f)] or findings
    chosen.sort(key=lambda f: (SEVERITY_RANK.get(str(f.get("severity", "info")), 9), str(f.get("file", "")), int(f.get("line") or 0)))

    # Deduplicate by file + line + CWE to keep the prompt compact.
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for f in chosen:
        key = (str(f.get("file", "")), int(f.get("line") or 0), str(f.get("cwe", "")))
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
        if len(result) >= limit:
            break
    return result


def safe_join(root: Path, rel: str) -> Path | None:
    root = root.resolve()
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def source_context(src_root: Path, rel_file: str, line: int, radius: int = 12) -> dict[str, Any]:
    path = safe_join(src_root, rel_file)
    if path is None or not path.exists() or not path.is_file():
        return {"available": False, "text": "", "start_line": 0, "end_line": 0}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"available": False, "text": "", "start_line": 0, "end_line": 0}
    if not lines:
        return {"available": True, "text": "", "start_line": 0, "end_line": 0}
    line = max(1, min(line or 1, len(lines)))
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    numbered = []
    for idx in range(start, end + 1):
        marker = ">" if idx == line else " "
        numbered.append(f"{marker}{idx:4d}: {lines[idx - 1]}")
    return {"available": True, "text": "\n".join(numbered), "start_line": start, "end_line": end}


def build_cases(src_root: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for f in findings:
        rel_file = str(f.get("file", ""))
        line = int(f.get("line") or 1)
        cases.append(
            {
                "rule_id": f.get("rule_id"),
                "cwe": f.get("cwe"),
                "severity": f.get("severity"),
                "language": f.get("language"),
                "file": rel_file,
                "line": line,
                "message": f.get("message"),
                "evidence": f.get("evidence"),
                "existing_recommendation": f.get("recommendation"),
                "context": source_context(src_root, rel_file, line),
            }
        )
    return cases


def build_prompt(cases: list[dict[str, Any]]) -> str:
    return (
        "你是编码安全课程助教和代码修复审阅员。请基于静态分析 findings 与源码上下文，"
        "生成用于课堂演示的修复 patch 候选。\n"
        "重要约束：\n"
        "1. 只输出 JSON，不要输出 Markdown，不要使用代码围栏。\n"
        "2. 每个 patch 必须是 unified diff，包含 diff --git、---、+++、@@。\n"
        "3. diff 只作为演示建议，不要求自动应用，但要尽量保持语法正确、修改最小。\n"
        "4. 不要删除功能；优先做输入校验、参数化查询、移除 shell=True、替换弱加密、关闭 debug。\n"
        "5. 如果某个 finding 不适合直接 patch，请在 unified_diff 中返回空字符串，并解释 review_notes。\n"
        "JSON 结构：{title, summary, patches:[{file,line,cwe,title,risk,repair_strategy,unified_diff,review_notes[]}]}。\n\n"
        "Findings 与源码上下文：\n"
        + json.dumps(cases, ensure_ascii=False, indent=2)
    )


def prompt_markdown(prompt: str, model: str, reason: str | None = None) -> str:
    lines = ["# Gemma Diff Suggestions", "", f"> Model: `{model}`"]
    if reason:
        lines += ["", f"> 未生成在线 diff：{reason}"]
    lines += [
        "",
        "Gemma/Gemini API 未可用时，课堂演示可以复制下面的 prompt 到 AI Studio。此步骤不会修改仓库。",
        "",
        "```text",
        prompt,
        "```",
        "",
    ]
    return "\n".join(lines)


def request_gemini(model: str, api_key: str, body: dict[str, Any]) -> dict[str, Any]:
    url = f"{API_BASE}/models/{model}:generateContent"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def response_text(data: dict[str, Any]) -> str:
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"Gemma response did not contain text: {data!r}") from exc


def parse_json_text(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise


def http_error_message(err: urllib.error.HTTPError) -> str:
    try:
        detail = err.read().decode("utf-8", errors="replace")
    except Exception:
        detail = ""
    if len(detail) > 1200:
        detail = detail[:1200] + "..."
    return f"HTTP {err.code} {err.reason}" + (f" - {detail}" if detail else "")


def combined_patch(obj: dict[str, Any]) -> str:
    chunks: list[str] = []
    for p in obj.get("patches", []):
        diff = str(p.get("unified_diff", "")).strip()
        if diff:
            chunks.append(diff)
    return "\n\n".join(chunks).strip() + ("\n" if chunks else "")


def render_markdown(obj: dict[str, Any], model: str) -> str:
    lines: list[str] = ["# Gemma Diff Suggestions", "", f"> Model: `{model}`", ""]
    lines.append(str(obj.get("summary") or "Gemma generated patch candidates for classroom review."))
    lines += ["", "> 这些 diff 仅用于课堂演示和人工 review；CI 不会自动应用，也不会创建 PR。", ""]

    patches = obj.get("patches", [])
    if not patches:
        lines += ["_No patch candidates were generated._", ""]
        return "\n".join(lines)

    for i, p in enumerate(patches, 1):
        file = str(p.get("file", "unknown"))
        line = p.get("line", "?")
        cwe = str(p.get("cwe", "CWE"))
        title = str(p.get("title", "Patch candidate"))
        lines += [f"## {i}. {cwe} · `{file}:{line}`", "", f"**{title}**", ""]
        lines += [f"- 风险：{p.get('risk', '')}", f"- 修复策略：{p.get('repair_strategy', '')}"]
        notes = p.get("review_notes") or []
        if notes:
            lines.append("- 人工审阅要点：")
            for note in notes:
                lines.append(f"  - {note}")
        diff = str(p.get("unified_diff", "")).strip()
        lines += [""]
        if diff:
            lines += ["```diff", diff, "```", ""]
        else:
            lines += ["_Gemma did not produce a direct diff for this finding._", ""]
    return "\n".join(lines).rstrip() + "\n"


def write_outputs(obj: dict[str, Any], out_md: Path, out_json: Path, out_patch: Path, model: str) -> None:
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_patch.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(obj, model), encoding="utf-8")
    out_json.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out_patch.write_text(combined_patch(obj), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Gemma/Gemini unified diff suggestions as GFM Markdown.")
    parser.add_argument("findings", nargs="?", default="analysis/findings.json")
    parser.add_argument("--src", default="samples", help="Source root used by the analyzer. Default: samples")
    parser.add_argument("--out-md", default="analysis/repair/gemma_diff_suggestions.md")
    parser.add_argument("--out-json", default="analysis/repair/gemma_diff_suggestions.json")
    parser.add_argument("--out-patch", default="analysis/repair/suggested.patch")
    parser.add_argument("--limit", type=int, default=int(os.environ.get("GEMMA_PATCH_LIMIT", "6")))
    args = parser.parse_args()

    model = os.environ.get("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    strict = os.environ.get("GEMINI_STRICT", "").lower() in {"1", "true", "yes"}
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    findings = pick_findings(load_findings(Path(args.findings)), max(1, args.limit))
    cases = build_cases(Path(args.src), findings)
    prompt = build_prompt(cases)

    out_md = Path(args.out_md)
    out_json = Path(args.out_json)
    out_patch = Path(args.out_patch)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    if not api_key:
        out_md.write_text(prompt_markdown(prompt, model, "未设置 GEMINI_API_KEY"), encoding="utf-8")
        out_json.write_text(json.dumps({"title": "Gemma Diff Suggestions", "summary": "No API key configured.", "patches": []}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        out_patch.write_text("", encoding="utf-8")
        print(f"Wrote prompt-only repair demo to {out_md}")
        return 0

    contents = [{"role": "user", "parts": [{"text": prompt}]}]
    attempts: list[tuple[str, dict[str, Any]]] = [
        (
            "responseJsonSchema",
            {
                "contents": contents,
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "responseJsonSchema": SCHEMA,
                    "temperature": 0.1,
                },
            },
        ),
        (
            "json mime only",
            {
                "contents": contents,
                "generationConfig": {"responseMimeType": "application/json", "temperature": 0.1},
            },
        ),
        (
            "plain prompt fallback",
            {
                "contents": contents,
                "generationConfig": {"temperature": 0.1},
            },
        ),
    ]

    errors: list[str] = []
    for label, body in attempts:
        try:
            data = request_gemini(model, api_key, body)
            obj = parse_json_text(response_text(data))
            # Normalize partially compliant model output.
            obj.setdefault("title", "Gemma Diff Suggestions")
            obj.setdefault("summary", "Gemma generated patch candidates for classroom review.")
            obj.setdefault("patches", [])
            write_outputs(obj, out_md, out_json, out_patch, model)
            print(f"Wrote Gemma diff suggestions to {out_md}")
            print(f"Wrote combined patch artifact to {out_patch}")
            return 0
        except urllib.error.HTTPError as err:
            msg = f"{label}: {http_error_message(err)}"
            errors.append(msg)
            print(f"[gemma_diff_suggest] {msg}", file=sys.stderr)
            if err.code in {401, 403, 404}:
                break
        except Exception as err:
            msg = f"{label}: {type(err).__name__}: {err}"
            errors.append(msg)
            print(f"[gemma_diff_suggest] {msg}", file=sys.stderr)

    reason = "; ".join(errors[-2:]) if errors else "unknown error"
    out_md.write_text(prompt_markdown(prompt, model, reason), encoding="utf-8")
    out_json.write_text(json.dumps({"title": "Gemma Diff Suggestions", "summary": reason, "patches": []}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out_patch.write_text("", encoding="utf-8")
    print(f"Gemma diff generation failed open; wrote prompt to {out_md}", file=sys.stderr)
    return 1 if strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
