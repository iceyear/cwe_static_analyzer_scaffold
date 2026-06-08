# CWE 静态分析大作业脚手架

在 GitHub Actions 上运行 CodeQL + 一个可解释的课程用 CWE 静态分析器，并可选导出 Soufflé Datalog facts / Gemini 中文报告。

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

## Soufflé 演示

```bash
just souffle
```

`Justfile` 会自动创建 `analysis/datalog`，避免 Soufflé 的输出目录不存在报错。

## GitHub Actions

把整个目录 push 到 GitHub。Actions 当前使用 `actions/checkout@v5`、`actions/setup-python@v6`、`github/codeql-action/*@v4` 和 `actions/upload-artifact@v6`，用于规避 Node.js 20 / CodeQL Action v3 的弃用警告。Actions 会执行：

1. CodeQL C/C++，使用 `build-mode: none`，避免 Windows 头文件导致 Linux 构建失败。
2. 自定义课程分析器，输出 JSON、Markdown、SARIF 和 Datalog facts。
3. 把 `analysis/report.md` 直接写入 GitHub Actions 的 Job Summary。
4. 如果配置了 `GEMINI_API_KEY`，自动生成 `analysis/gemini_report.md` 并追加到 Job Summary。
5. 上传 SARIF 到 GitHub Code Scanning 页面。

## Gemini 报告

本地运行：

```bash
# 无 API key：打印可复制的 prompt
just gemini

# 有 API key：生成结构化中文报告
export GEMINI_API_KEY="..."
just gemini
```

GitHub Actions 运行：

1. 在仓库 `Settings → Secrets and variables → Actions → New repository secret` 添加 `GEMINI_API_KEY`。
2. 可选：在 `Variables` 添加 `GEMINI_MODEL`，例如 `gemini-2.5-flash`。
3. CI 会在密钥存在时执行 `just gemini`，并把 `analysis/gemini_report.md` 追加到 Actions Summary。
4. 如果没有密钥，CI 会跳过 Gemini，不会导致构建失败。

## 常用 just 命令

```bash
just analyze   # 生成 findings.json、report.md、custom-cwe.sarif 和 facts
just report    # 打印 Markdown 报告
just souffle   # 运行 Soufflé Datalog 推理
just gemini    # 生成 Gemini 中文报告或 prompt
just demo      # 课堂演示入口
just clean     # 清理生成物
```
