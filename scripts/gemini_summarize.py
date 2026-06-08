#!/usr/bin/env python3
"""Optional Gemini/Gemma report generator.

Usage:
  python scripts/gemini_summarize.py analysis/findings.json > analysis/gemini_report.md

Environment:
  GEMINI_API_KEY        Google AI Studio API key. If absent, this prints a pasteable prompt.
  GEMINI_MODEL          Defaults to gemma-4-31b-it. Override with gemini-* or another supported model.
  GEMINI_STRICT=1       Make API failures exit non-zero. Default is fail-open for CI demos.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

DEFAULT_MODEL = "gemma-4-31b-it"
API_BASE = "https://generativelanguage.googleapis.com/v1beta"

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "executive_summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cwe": {"type": "string"},
                    "location": {"type": "string"},
                    "risk": {"type": "string"},
                    "fix": {"type": "string"},
                },
                "required": ["cwe", "location", "risk", "fix"],
            },
        },
        "demo_script": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["title", "executive_summary", "findings", "demo_script"],
}


def build_prompt(findings: Any) -> str:
    return (
        "你是编码安全课程助教。请基于以下静态分析结果生成中文演示报告。\n"
        "要求：\n"
        "1. 每个漏洞包含 CWE、位置、风险、修复建议。\n"
        "2. 给出 5 步课堂演示脚本。\n"
        "3. 只输出 JSON，不要输出 Markdown，不要使用代码围栏。\n"
        "JSON 结构必须包含 title、executive_summary、findings、demo_script。\n\n"
        "静态分析结果如下：\n"
        + json.dumps(findings, ensure_ascii=False, indent=2)
    )


def prompt_markdown(prompt: str, reason: str | None = None) -> str:
    out = ["# Gemini Prompt"]
    if reason:
        out.extend(["", f"> Gemini API 未生成在线报告：{reason}", "", "可复制下面的 prompt 到 AI Studio 或本地模型继续演示。"])
    out.extend(["", "```text", prompt, "```"])
    return "\n".join(out) + "\n"


def request_gemini(model: str, api_key: str, body: dict[str, Any]) -> dict[str, Any]:
    url = f"{API_BASE}/models/{model}:generateContent"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def response_text(data: dict[str, Any]) -> str:
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"Gemini response did not contain candidate text: {data!r}") from exc


def parse_json_text(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Last-resort extraction for models that wrap JSON in prose.
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise


def render_report(obj: dict[str, Any], model: str) -> str:
    lines: list[str] = [f"# {obj.get('title', 'Gemini assisted CWE report')}", ""]
    lines.append(f"> Model: `{model}`")
    lines.append("")
    lines.append(str(obj.get("executive_summary", "")))
    lines.append("")
    for finding in obj.get("findings", []):
        cwe = finding.get("cwe", "CWE")
        location = finding.get("location", "unknown location")
        lines.append(f"## {cwe} · {location}")
        lines.append("")
        lines.append(f"- 风险：{finding.get('risk', '')}")
        lines.append(f"- 修复：{finding.get('fix', '')}")
        lines.append("")
    lines.append("## 演示脚本")
    lines.append("")
    for i, step in enumerate(obj.get("demo_script", []), 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    return "\n".join(lines)


def api_error_message(err: urllib.error.HTTPError) -> str:
    try:
        detail = err.read().decode("utf-8", errors="replace")
    except Exception:
        detail = ""
    return f"HTTP {err.code} {err.reason}" + (f" - {detail}" if detail else "")


def main() -> int:
    findings_path = sys.argv[1] if len(sys.argv) > 1 else "analysis/findings.json"
    with open(findings_path, encoding="utf-8") as f:
        findings = json.load(f)

    prompt = build_prompt(findings)
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    model = os.environ.get("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    strict = os.environ.get("GEMINI_STRICT", "").lower() in {"1", "true", "yes"}

    if not api_key:
        print(prompt_markdown(prompt, f"未设置 GEMINI_API_KEY；默认模型会是 {model}"))
        return 0

    # Do not use generationConfig.responseFormat here.
    # In the REST API that field is for modality-specific response formats; its
    # text.mimeType enum rejects the ordinary MIME string "application/json".
    # For JSON text generation, the most compatible REST fields are
    # responseMimeType + responseJsonSchema.  A snake_case variant is kept as a
    # compatibility fallback because Google examples have historically shown
    # both spellings in REST snippets.
    contents = [{"role": "user", "parts": [{"text": prompt}]}]
    attempts: list[tuple[str, dict[str, Any]]] = [
        (
            "responseJsonSchema",
            {
                "contents": contents,
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "responseJsonSchema": SCHEMA,
                    "temperature": 0.2,
                },
            },
        ),
        (
            "response_json_schema compatibility",
            {
                "contents": contents,
                "generation_config": {
                    "response_mime_type": "application/json",
                    "response_json_schema": SCHEMA,
                    "temperature": 0.2,
                },
            },
        ),
        (
            "json mime only",
            {
                "contents": contents,
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "temperature": 0.2,
                },
            },
        ),
        (
            "plain prompt fallback",
            {
                "contents": contents,
                "generationConfig": {"temperature": 0.2},
            },
        ),
    ]

    errors: list[str] = []
    for label, body in attempts:
        try:
            data = request_gemini(model, api_key, body)
            obj = parse_json_text(response_text(data))
            print(render_report(obj, model))
            return 0
        except urllib.error.HTTPError as err:
            msg = f"{label}: {api_error_message(err)}"
            errors.append(msg)
            print(f"[gemini_summarize] {msg}", file=sys.stderr)
            # A model/API-key problem is unlikely to be fixed by changing JSON config.
            if err.code in {401, 403, 404}:
                break
        except Exception as err:  # keep CI demo fail-open by default
            msg = f"{label}: {type(err).__name__}: {err}"
            errors.append(msg)
            print(f"[gemini_summarize] {msg}", file=sys.stderr)

    reason = "; ".join(errors[-2:]) if errors else "unknown error"
    print(prompt_markdown(prompt, reason))
    return 1 if strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
