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

把整个目录 push 到 GitHub。Actions 会执行：

1. CodeQL C/C++，使用 `build-mode: none`，避免 Windows 头文件导致 Linux 构建失败。
2. 自定义课程分析器，输出 JSON、Markdown、SARIF 和 Datalog facts。
3. 上传 SARIF 到 GitHub Code Scanning 页面。

## Gemini 报告

```bash
# 无 API key：打印可复制的 prompt
just gemini

# 有 API key：生成结构化中文报告
export GEMINI_API_KEY="..."
just gemini
```

## 常用 just 命令

```bash
just analyze   # 生成 findings.json、report.md、custom-cwe.sarif 和 facts
just report    # 打印 Markdown 报告
just souffle   # 运行 Soufflé Datalog 推理
just gemini    # 生成 Gemini 中文报告或 prompt
just demo      # 课堂演示入口
just clean     # 清理生成物
```
