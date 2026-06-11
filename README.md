# CWE 静态分析大作业脚手架

在 GitHub Actions 上运行 CodeQL + 一个可解释的课程用 CWE 静态分析器，并可选导出 Soufflé Datalog facts / Gemini-Gemma 中文报告。

当前自定义分析器支持：

- C/C++：`*.c`, `*.cc`, `*.cpp`, `*.cxx`, `*.h`, `*.hpp`, `*.hh`
- Java：`*.java`
- Python：`*.py`

## 多语言 CWE 覆盖

| 语言 | 示例规则 | CWE |
|---|---|---|
| C/C++ | `cin >> char[]`, `strcpy`, 未校验 `scanf`, `rand`, Windows 强制线程 API | CWE-120, CWE-787, CWE-20, CWE-330, CWE-362 |
| Java | `Runtime.exec`, `ProcessBuilder`, SQL 拼接, `ObjectInputStream/readObject`, `MessageDigest(MD5/SHA-1)`, `Random`, 硬编码密钥, 用户输入文件路径 | CWE-78, CWE-89, CWE-502, CWE-327, CWE-338, CWE-798, CWE-22 |
| Python | `os.system`, `subprocess(..., shell=True)`, `eval/exec`, `pickle/yaml.load`, 动态 SQL, `hashlib.md5/sha1`, `random`, `requests verify=False`, Flask debug, 硬编码密钥 | CWE-78, CWE-94, CWE-502, CWE-89, CWE-327, CWE-338, CWE-295, CWE-489, CWE-798 |

这些规则是课程演示用的 explainable heuristic rules，不替代生产级 SAST；真正的 CI 安全扫描由 GitHub CodeQL 同时运行。

## 本地运行：推荐使用 just

Arch/Crostini 安装：

```bash
sudo pacman -S --needed just python souffle
```

查看命令：

```bash
just
```

一键课堂演示：

```bash
just demo
```

只跑静态分析器：

```bash
just analyze
just report
```

默认扫描 `samples/`，其中包含 C/C++、Java、Python 三组样例。你也可以直接指定自己的目录或文件：

```bash
python scripts/analyze_cwe.py path/to/project \
  --json analysis/findings.json \
  --markdown analysis/report.md \
  --sarif analysis/custom-cwe.sarif \
  --facts analysis/facts || true
```

## Soufflé 演示

```bash
just souffle
```

`Justfile` 会自动创建 `analysis/datalog`，避免 Soufflé 的输出目录不存在报错。

现在 Datalog facts 也扩展为多语言：

```text
array_decl.facts
unbounded_read.facts
unsafe_call.facts
untrusted_int.facts
var_as_bound.facts
tainted_sink.facts
hardcoded_secret.facts
weak_crypto.facts
```

课堂讲法可以是：不同语言前端先抽取统一事实，例如 `unsafe_call`、`tainted_sink`、`weak_crypto`，再由 Soufflé 规则推导出跨语言 CWE 告警。

## GitHub Actions

把整个目录 push 到 GitHub。Actions 会执行：

1. CodeQL 多语言扫描：C/C++、Java/Kotlin、Python。
2. C/C++ 与 Java/Kotlin 使用 no-build 模式，减少样例中 Windows 头文件、无构建系统 Java 代码对 CI 的影响；Python 不需要构建。
3. 自定义课程分析器，输出 JSON、Markdown、SARIF 和 Datalog facts。
4. 如果配置了 `GEMINI_API_KEY`，生成 Gemini/Gemma 辅助中文解释报告。
5. 把 `analysis/report.md` 和 `analysis/gemini_report.md` 写入 GitHub Actions Summary。
6. 上传 SARIF 到 GitHub Code Scanning 页面。

## Gemini / Gemma 报告

```bash
# 无 API key：打印可复制的 prompt
just gemini

# 有 API key：生成结构化中文报告
export GEMINI_API_KEY="..."
just gemini
```

默认模型是：

```bash
GEMINI_MODEL=gemma-4-31b-it
```

你可以覆盖它：

```bash
export GEMINI_MODEL="gemini-2.5-flash"
just gemini
```

GitHub Actions 中推荐这样配置：

- Repository secret: `GEMINI_API_KEY`
- Repository variable，可选: `GEMINI_MODEL`

如果 Gemini/Gemma API 返回 400、429、500 等错误，脚本默认会 fail-open：生成一份可复制 prompt 的 Markdown，而不会让课程演示 CI 直接失败。若你想让 API 错误直接失败，可设置：

```bash
export GEMINI_STRICT=1
```

## 常用 just 命令

```bash
just analyze   # 生成 findings.json、report.md、custom-cwe.sarif 和 facts
just report    # 打印 Markdown 报告
just souffle   # 运行 Soufflé Datalog 推理
just gemini    # 生成 Gemini/Gemma 中文报告或 prompt
just demo      # 课堂演示入口
just clean     # 清理生成物
```

## Gemini/Gemma API note

`just gemini` defaults to `gemma-4-31b-it` when `GEMINI_MODEL` is not set. It uses the REST-compatible JSON generation fields `responseMimeType` and `responseJsonSchema` first, then falls back to prompt-only JSON if a specific model rejects structured output. The deprecated/incorrect `generationConfig.responseFormat.text.mimeType = "application/json"` form is intentionally not used.
