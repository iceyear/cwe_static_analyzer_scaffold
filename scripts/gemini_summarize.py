#!/usr/bin/env python3
"""Optional Gemini report generator.
Set GEMINI_API_KEY and run:
  python scripts/gemini_summarize.py analysis/findings.json > analysis/gemini_report.md
Optional: set GEMINI_MODEL, defaults to gemini-2.5-flash.
If no API key is set, it prints the exact prompt you can paste into Gemini.
"""
from __future__ import annotations
import json
import os
import sys
import urllib.request

SCHEMA = {
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
                    "fix": {"type": "string"}
                },
                "required": ["cwe", "location", "risk", "fix"]
            }
        },
        "demo_script": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["title", "executive_summary", "findings", "demo_script"]
}


def main() -> int:
    findings_path = sys.argv[1] if len(sys.argv) > 1 else "analysis/findings.json"
    findings = json.load(open(findings_path, encoding="utf-8"))
    prompt = (
        "你是编码安全课程助教。请基于以下静态分析结果生成中文演示报告，"
        "每个漏洞要包含 CWE、位置、风险、修复建议，并给出 5 步课堂演示脚本。\n\n"
        + json.dumps(findings, ensure_ascii=False, indent=2)
    )
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("# Gemini Prompt\n")
        print(prompt)
        return 0

    model = os.environ.get("GEMINI_MODEL")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseFormat": {
                "text": {
                    "mimeType": "application/json",
                    "schema": SCHEMA
                }
            }
        }
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.load(r)
    text = data["candidates"][0]["content"]["parts"][0]["text"]
    obj = json.loads(text)
    print(f"# {obj['title']}\n")
    print(obj["executive_summary"] + "\n")
    for f in obj["findings"]:
        print(f"## {f['cwe']} · {f['location']}\n")
        print(f"- 风险：{f['risk']}")
        print(f"- 修复：{f['fix']}\n")
    print("## 演示脚本\n")
    for i, step in enumerate(obj["demo_script"], 1):
        print(f"{i}. {step}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
