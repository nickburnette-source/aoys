# AOYS — Angel on Your Shoulder

> **A fully local AI security scanner for VS Code.** No cloud. No telemetry. No API keys. Just a local Ollama model watching your code for real exploitable vulnerabilities — while you work.

![VS Code](https://img.shields.io/badge/VS%20Code-1.85+-blue?logo=visualstudiocode)
![License](https://img.shields.io/badge/license-MIT-green)
![Local Only](https://img.shields.io/badge/data-stays%20local-important)

---

## What It Does

AOYS runs your code through a local LLM (Gemma 4 by default) with an **attacker's mindset**. It doesn't just run pattern matching — it reasons about your code the way a red-teamer would, catching design-level vulnerabilities that static rules cannot.

It augments LLM reasoning with **Semgrep's public security rule packs**, giving you the best of both: rules-based precision and AI-powered depth.

Results appear directly in VS Code's Problems panel with file and line numbers — no separate dashboard, no context switching.

---

## Features

### 🔒 Attacker-Mindset Analysis
Goes beyond traditional SAST. Finds exploitable vulnerabilities across categories:
- **Injection** — SQL, command, LDAP, XPath, template injection
- **Authentication & Authorization** — broken access controls, privilege escalation paths, JWT misuse
- **Cryptographic weaknesses** — hardcoded secrets, weak algorithms, predictable tokens, improper cert validation
- **Data exposure** — credentials or PII in logs, sensitive data in URLs, verbose error messages leaking internals
- **Insecure design** — wrong-layer security decisions, overly broad permissions, trust boundary violations
- **Input/output handling** — unvalidated inputs reaching dangerous sinks, output encoding failures, prototype pollution
- **Security misconfigurations** — permissive CORS, debug modes in production, insecure defaults, missing security headers

### 🧠 Semgrep Rules Integration
Automatically fetches Semgrep's top security rules for each detected language and injects them into the model prompt. The model applies the rules AND reasons beyond them — catching design-level issues static rules can't see.

### 🏠 Fully Local — Your Code Never Leaves
All scanning runs against your local [Ollama](https://ollama.com) instance. Nothing is sent to any external server. No API key required. Works fully air-gapped.

### ⚡ Two Scan Modes
| Mode | Command | When to Use |
|------|---------|-------------|
| **Scan Changed Files** | `AOYS: Scan Changed Files` | After every commit / PR review — scans only git-modified files |
| **Full Project Scan** | `AOYS: Full Project Scan` | Initial scan, branch switch, or periodic audit |

### 🔄 Parallel Scanning
Files are scanned concurrently (default: 3 workers, configurable up to 10). A bounded worker pool keeps your Ollama instance from being overwhelmed. Each file's output is prefixed `[N/M]` so concurrent results stay traceable.

### 💾 Content-Hash Cache
Full scans skip the LLM for files that haven't changed since the last scan. Cache is stored in `.aoys/scan-cache.json` and keyed by content hash — file renames and moves still invalidate correctly.

### 📋 SARIF Reports
Every scan produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report in `.aoys/aoys-{timestamp}.sarif`. Open it in any SARIF-compatible viewer, attach it to a PR, or keep it as an audit record. An **Open Report** button appears in the notification when issues are found.

### 🔍 Problems Panel Integration
Issues appear as VS Code diagnostics — gutter icons, Problems panel entries, and squiggles — so you can navigate directly to the vulnerable line. Clicking a problem jumps to the file and line.

### 🤔 Live Thinking Output
If your model supports reasoning (Gemma 4 thinking mode), AOYS streams the model's thought process to the output panel in real time — throttled to one update per 3 seconds so it doesn't flood the log.

### 🚫 Smart File Exclusion
- **Binary files** automatically excluded (images, archives, compiled artifacts, fonts, etc.)
- **`.gitignore`** file itself always excluded
- **`.aoys/`** directory always excluded (reports, cache)
- **`.aoys/.aoysignore`** — add your own exclusions using standard gitignore syntax (`*.generated.ts`, `vendor/`, `**/fixtures/`, etc.)

### 🌐 Broad Language Support
Scans every non-binary file in your project. Language-specific Semgrep rules are fetched for:

Python · JavaScript · TypeScript · Go · Java · Ruby · Rust · PHP · C · C++ · C# · Swift · Kotlin · Scala · Bash · HCL/Terraform · YAML · HTML · Dockerfile

All other file types (config, lockfiles, SQL, etc.) are still scanned by the LLM without language-specific rules.

### 🔁 Model Auto-Selection
Set model to `"auto"` and AOYS will query your Ollama instance and pick the best available Gemma 4 model automatically. Or pin a specific model by name.

### ⚙️ Non-Blocking
Scans run entirely in the background. The progress notification can be dismissed — scanning continues silently. You can keep coding, debugging, or running tests while a scan is in progress.

---

## Requirements

1. **[Ollama](https://ollama.com)** — installed and running
2. **Gemma 4** (recommended) — pull it once:
   ```
   ollama pull gemma4
   ```
   Any OpenAI-compatible endpoint works (LM Studio, llama.cpp server, remote Ollama, etc.)

---

## Installation

Install from the VS Code Marketplace: search **AOYS** or find it [here](#).

Then install a model if you haven't:
```
ollama pull gemma4
```

---

## Quick Start

1. Open a project in VS Code
2. Click the **$(shield) AOYS** button in the status bar (bottom right)
3. AOYS scans your git-changed files and reports issues in the Problems panel

Or open the Command Palette (`Cmd/Ctrl+Shift+P`) and run:
- `AOYS: Scan Changed Files` — scan only modified files
- `AOYS: Full Project Scan` — scan the entire project
- `AOYS: Select Model` — pick from models available in your Ollama instance
- `AOYS: Show Output` — open the AOYS output panel

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `aoys.baseUrl` | `http://localhost:11434/v1` | OpenAI-compatible endpoint. Change to your Ollama IP/port or any compatible server |
| `aoys.model` | `auto` | Model name, or `auto` to pick the best Gemma 4 from your instance |
| `aoys.temperature` | `0.1` | Sampling temperature. Keep low for reliable JSON output |
| `aoys.scanConcurrency` | `3` | Files to scan in parallel (1–10). Higher = faster scans if your GPU can handle it |

**Remote Ollama example** (scanning from a laptop, GPU on a desktop):
```json
{
  "aoys.baseUrl": "http://192.168.1.100:11434/v1",
  "aoys.scanConcurrency": 5
}
```

---

## Excluding Files — `.aoys/.aoysignore`

Create `.aoys/.aoysignore` in your project root. Uses standard gitignore syntax:

```gitignore
# Skip generated files
*.generated.ts
*.min.js

# Skip test fixtures and vendored code
**/fixtures/
vendor/
third_party/

# Skip a specific directory
docs/
```

---

## Output Format

The AOYS output panel shows a live feed during scanning:

```
────────────────────────────────────────────────────────────
AOYS Full Scan · gemma4:31b · 3:42:01 PM
24 file(s) to scan · 3 concurrent
────────────────────────────────────────────────────────────
Fetching Semgrep rules for: python, typescript, dockerfile
  📋 Loaded 30 Semgrep rules for python
  📋 Loaded 28 Semgrep rules for typescript
  📋 Loaded 6 Semgrep rules for dockerfile

[1/24] app/auth.py (python, 30 rules)
[2/24] app/db.py (python, 30 rules)
[3/24] Dockerfile (dockerfile, 6 rules)
[1/24]     💭 checking for SQL query construction with user input...
[3/24]     ✓ 0 issue(s) · 62s
[1/24]     ✓ 2 issue(s) · 95s
[1/24]       [error] SQL injection via unsanitized user input (line 42)
[1/24]       [warning] Hardcoded database password (line 8)
...
────────────────────────────────────────────────────────────
Done · 4 total issue(s) · 3:58:22 PM
📄 SARIF report: /workspace/.aoys/aoys-2026-05-10T20-42-01.sarif
```

---

## Privacy

AOYS is **private by design**:
- All inference runs on your local Ollama instance
- No code, file paths, or scan results are transmitted anywhere
- Semgrep rule packs are fetched from `semgrep.dev` (rule definitions only — no code is sent)
- The `.aoys/` directory (cache + reports) is git-ignored automatically

---

## How It Works

1. **File discovery** — walks the workspace, filters binary files and ignore patterns
2. **Language detection** — maps file extension to Semgrep language pack
3. **Rules fetch** — downloads top security rules for each language (cached in memory)
4. **Parallel scan** — bounded worker pool sends each file to Ollama with an attacker-mindset prompt + Semgrep rules
5. **Response parsing** — streams SSE output, strips `<think>` tokens, parses structured JSON
6. **Results** — issues applied to VS Code diagnostics, SARIF report written to `.aoys/`

---

## License

MIT — see [LICENSE](LICENSE)
