# CWE 静态分析大作业脚手架

```text
C/C++ / Java / Python 源码
        ↓
Python / AST / regex 前端抽取 facts
        ↓
Soufflé Datalog 规则推理 CWE findings
        ↓
JSON / Markdown / SARIF / GitHub Actions Summary
        ↓
Gemma/Gemini 解释与 unified diff 展示
```

CodeQL 作为 GitHub Actions 中的工业级基线扫描器并行运行；自研部分用于展示可解释的 facts、Datalog 规则推理、SARIF 输出和 Gemma 课堂演示。

## 当前支持语言

- C/C++：`*.c`, `*.cc`, `*.cpp`, `*.cxx`, `*.h`, `*.hpp`, `*.hh`
- Java：`*.java`
- Python：`*.py`

## 多语言 CWE 覆盖

| 语言 | 示例 facts / sinks | CWE |
|---|---|---|
| C/C++ | `cin >> char[]`, `strcpy/strcat/sprintf/gets`, 未校验 `scanf`, 输入控制数组边界, `rand`, Windows 强制线程 API | CWE-120, CWE-787, CWE-20, CWE-252, CWE-330, CWE-362 |
| Java | `Runtime.exec`, `ProcessBuilder`, SQL 拼接, `ObjectInputStream/readObject`, `MessageDigest(MD5/SHA-1)`, `Random`, 硬编码密钥, 用户输入文件路径 | CWE-78, CWE-89, CWE-502, CWE-327, CWE-338, CWE-798, CWE-22 |
| Python | `os.system`, `subprocess(..., shell=True)`, `eval/exec`, `pickle/yaml.load`, 动态 SQL, `hashlib.md5/sha1`, `random`, `requests verify=False`, Flask debug, 硬编码密钥 | CWE-78, CWE-94, CWE-502, CWE-89, CWE-327, CWE-338, CWE-295, CWE-489, CWE-798 |

## 目录结构

```text
scripts/extract_facts.py       # Python/AST/regex 前端，只负责抽 facts
rules/cwe_rules.dl             # Soufflé Datalog 形式化规则，负责推导 CWE
scripts/facts_to_results.py    # finding.csv -> JSON/Markdown/SARIF
scripts/analyze_cwe.py         # 编排入口：extract -> souffle/fallback -> render
scripts/gemini_summarize.py    # Gemma/Gemini 中文解释报告
scripts/gemma_diff_suggest.py  # Gemma/Gemini unified diff 课堂展示
```

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

默认扫描 `samples/`。你也可以直接指定自己的目录或文件：

```bash
just --set src path/to/project analyze
```

或使用 Python 入口：

```bash
python scripts/analyze_cwe.py path/to/project \
  --json analysis/findings.json \
  --markdown analysis/report.md \
  --sarif analysis/custom-cwe.sarif \
  --facts analysis/facts \
  --datalog analysis/datalog || true
```

## 形式化推理层：facts + Soufflé

只抽 facts：

```bash
just facts
```

输出示例：

```text
analysis/facts/array_decl.facts
analysis/facts/unbounded_read.facts
analysis/facts/unsafe_call.facts
analysis/facts/untrusted_int.facts
analysis/facts/var_as_bound.facts
analysis/facts/tainted_sink.facts
analysis/facts/hardcoded_secret.facts
analysis/facts/weak_crypto.facts
analysis/facts/syntax_warning.facts
analysis/facts/manifest.json
```

只跑 Soufflé 推理：

```bash
just infer
```

完整 Soufflé 路径：

```bash
just souffle
```

如果本机没有安装 Soufflé，`just analyze` 会自动使用 `facts_to_results.py` 中与 `rules/cwe_rules.dl` 等价的 Python fallback，仍然生成同形的：

```text
analysis/datalog/finding.csv
analysis/findings.json
analysis/report.md
analysis/custom-cwe.sarif
```

## 常用 just 命令

```bash
just facts             # 只抽取 facts
just infer             # 只运行 Soufflé，生成 finding.csv
just render            # 将 finding.csv 转换为 JSON/Markdown/SARIF
just analyze           # facts -> Soufflé 若可用 -> fallback 若不可用 -> 报告/SARIF
just analyze-fallback  # 强制使用 Python fallback，对比调试用
just report            # 打印 Markdown 报告
just souffle           # 强制运行 Soufflé 正式推理路径
just gemini            # 生成 Gemma/Gemini 中文报告或 prompt
just repair-demo       # 生成 Gemma/Gemini unified diff 课堂展示
just demo              # 课堂演示入口
just clean             # 清理生成物
```

## GitHub Actions

把整个目录 push 到 GitHub。Actions 会执行：

1. CodeQL 多语言扫描：C/C++、Java/Kotlin、Python。
2. C/C++ 与 Java/Kotlin 使用 `build-mode: none`，减少 Windows 头文件和无构建系统样例对 CI 的影响；Python 不需要构建。
3. 自研课程分析器：Python/AST/regex 抽 facts，尝试 Soufflé Datalog 推理，若 runner 无 Soufflé 则 fallback。
4. 输出 JSON、Markdown、SARIF、facts 和 `analysis/datalog/finding.csv`。
5. 如果配置了 `GEMINI_API_KEY`，生成 Gemma/Gemini 中文解释报告和 diff 展示。
6. 把 `analysis/report.md`、Gemma 报告、diff 建议写入 GitHub Actions Summary。
7. 上传 `analysis/custom-cwe.sarif` 到 GitHub Code Scanning 页面。

CodeQL 的具体告警主要在 **Security → Code scanning** 查看；Actions Summary 展示的是自研 facts/Datalog 推理和 Gemma 解释/修复建议。

### GitHub Actions 中安装 Soufflé

GitHub Hosted Runner 的默认 Ubuntu apt 源通常没有 `souffle` 包；workflow 会先加入 Soufflé 官方 apt 仓库，再尝试安装：

```bash
sudo wget https://souffle-lang.github.io/ppa/souffle-key.public -O /usr/share/keyrings/souffle-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/souffle-archive-keyring.gpg] https://souffle-lang.github.io/ppa/ubuntu/ stable main" | sudo tee /etc/apt/sources.list.d/souffle.list
sudo apt-get update
sudo apt-get install -y souffle
```

如果安装失败，CI 会自动退回 Python fallback；如果安装成功，报告里的推理后端会显示为 `souffle`。

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

## Gemma diff 建议展示

本项目支持一个 Gemma 驱动的“辅助修复展示”流程：

```bash
just repair-demo
```

它会读取 `analysis/findings.json` 和对应源码上下文，请 Gemma/Gemini 输出 unified diff 候选，并生成：

```text
analysis/repair/gemma_diff_suggestions.md
analysis/repair/gemma_diff_suggestions.json
analysis/repair/suggested.patch
```

注意：这个流程只用于展示 **Gemma-assisted patch suggestion**，不会执行 `git apply`，不会修改工作区，也不会创建 Pull Request。GitHub Actions 会把 `gemma_diff_suggestions.md` 追加到 Job Summary。

候选 finding 会按语言均衡选择，避免 diff 只覆盖 C/C++ 而忽略 Java/Python。可用环境变量调整：

```bash
GEMMA_PATCH_LIMIT=9 GEMMA_PATCH_PER_LANGUAGE=3 just repair-demo
```

## 项目定位

本项目不是生产级 SAST，不承诺完整审计任意大型开源项目。合理定位是：

```text
CodeQL：工业级多语言基线扫描
自研前端：抽取 explainable facts
Soufflé：形式化 Datalog 规则推理 CWE
Gemma：解释和 diff 展示，不决定漏洞是否存在
```

因此，clone 一个真实多语言 GitHub 项目后可以运行：

```bash
just --set src external/project analyze
```

它能给出轻量 CWE pattern scan、facts、SARIF 和报告；完整审计结论应结合 CodeQL 结果与人工 review。
