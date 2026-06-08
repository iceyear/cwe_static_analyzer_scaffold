# CWE 静态分析大作业脚手架

在 GitHub Actions 上运行 CodeQL + 一个可解释的课程用 CWE 静态分析器，并可选导出 Soufflé Datalog facts / Gemini-Gemma 中文报告。

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

把整个目录 push 到 GitHub。Actions 会执行：

1. CodeQL C/C++，使用 `build-mode: none`，避免 Windows 头文件导致 Linux 构建失败。
2. 自定义课程分析器，输出 JSON、Markdown、SARIF 和 Datalog facts。
3. 如果配置了 `GEMINI_API_KEY`，生成 Gemini/Gemma 辅助中文解释报告。
4. 把 `analysis/report.md` 和 `analysis/gemini_report.md` 写入 GitHub Actions Summary。
5. 上传 SARIF 到 GitHub Code Scanning 页面。

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
