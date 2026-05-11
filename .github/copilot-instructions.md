# AOYS – Copilot Instructions

AOYS ("Angel on Your Shoulder") is a VS Code extension that scans git-changed files using a local LLM (via Ollama or any OpenAI-compatible endpoint) and surfaces findings as VS Code diagnostics in the Problems panel.

## Build Commands

```bash
npm run compile      # one-time TypeScript build → dist/
npm run watch        # incremental watch mode (use during development)
npm run vscode:prepublish  # production build before packaging
```

No test suite exists yet.

## Architecture

The entire extension lives in **`src/extension.ts`** and compiles to `dist/extension.js`.

**Data flow:**

1. User triggers `aoys.scanChanged` command (or clicks the status bar button)
2. `simple-git` queries the workspace's git status for staged/modified/created files, filtered to a set of supported extensions (`.ts .js .py .go .java .cpp .cs .php .rb .rs .swift .kt`)
3. For each file, both the full document text and the `git diff` are sent to the configured OpenAI-compatible endpoint
4. The LLM is instructed (via `GEMMA4_AUDITOR_PROMPT`) to return **only** a JSON object matching a fixed schema (see below)
5. `applyDiagnostics()` converts the JSON issues into `vscode.Diagnostic` objects, grouped by file path in a `Map<string, vscode.Diagnostic[]>`, then pushed to a single `vscode.DiagnosticCollection`

## LLM Response Schema

The prompt enforces this exact JSON shape — any code that parses or generates AI output must conform to it:

```jsonc
{
  "issues": [
    {
      "ruleId": "string",
      "severity": "error" | "warning" | "info",
      "category": "security" | "bug" | "performance" | "maintainability" | "style" | "deprecated" | "architecture" | "other",
      "file": "string",          // workspace-relative path
      "startLine": number,       // 1-indexed
      "endLine": number,         // 1-indexed
      "startColumn": number,     // 1-indexed
      "message": "short title",
      "description": "detailed explanation",
      "fix": {
        "description": "brief explanation",
        "patch": "unified diff OR null"
      } | null
    }
  ]
}
```

Line/column numbers from the LLM are **1-indexed**; `applyDiagnostics` converts them to 0-indexed `vscode.Position` values.

## Key Conventions

- **Low temperature is intentional.** The default `0.1` temperature is set to maximize JSON consistency. Don't raise it without good reason.
- **`response_format: { type: 'json_object' }`** is passed on every request to enforce structured output from the model.
- **`diagnosticCollection` is module-level** and cleared on every scan — it is not additive across scans.
- **`aoys.scanFullProject`** is a stub that shows an info message; full-project scanning is not yet implemented.
- The VS Code configuration keys (`aoys.baseUrl`, `aoys.model`, `aoys.temperature`) are the authoritative way to change endpoint/model — don't hardcode these in logic.


## Notes

UX is important here. The extension should be used with minimal additional user setup. This means the user should just install gemma 4 model locally via Ollama, install the extension, and it should "just work" with zero config. The default model should be set to "gemma 4" and the default endpoint should be set to "http://localhost:11434" (Ollama's default) — but these should be easily configurable for users with different setups. For example, my setup is another device running on 192.168.1.234 that has ollama + gemma 4, hence the setting to change away from localhost.