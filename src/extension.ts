import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import simpleGit from 'simple-git';
import * as crypto from 'crypto';

// ---------------------------------------------------------------------------
// Prompt templates
// ---------------------------------------------------------------------------

// Security analyzer prompt — attacker-mindset, broader than traditional SAST.
// Covers implementation flaws, design weaknesses, insecure defaults, and misconfigurations.
const SYSTEM_PROMPT = `You are a security analyzer with an attacker's mindset. Your job: find code, design decisions, and configurations an attacker could realistically exploit to compromise the application, its data, or its users.

Think like a red team. Ask: "If I were attacking this system, what would I use here?"

Look for:
- Missing or broken controls: authentication gaps, authorization bypasses, missing rate limits on sensitive operations, CSRF gaps
- Exploitable implementation flaws: injection sinks, unsafe deserialization, dangerous API misuse (eval, shell=True, pickle.loads), path traversal
- Insecure design: wrong-layer security decisions, overly broad permissions, trust boundary violations, privilege escalation paths
- Cryptographic weaknesses: weak or deprecated algorithms, hardcoded keys/secrets, predictable tokens, improper certificate validation
- Data exposure: credentials or PII in logs, cleartext sensitive data, verbose error messages revealing internals, sensitive values in URLs
- Security misconfigurations: permissive CORS, debug modes reachable in production, insecure defaults, missing security headers
- Input and output handling: unvalidated inputs reaching dangerous sinks, output encoding failures, prototype pollution

Where Semgrep rules are provided, apply them. Do not limit yourself to those rules — Semgrep cannot catch design-level weaknesses.

Do NOT report: style, naming, performance, maintainability, dead code, or anything without a plausible exploitation path.

Output ONLY valid JSON. No markdown fences. No preamble. No trailing text.

Vulnerabilities found — use this exact structure:
{"issues":[{"ruleId":"CWE-89","severity":"error","category":"injection","file":"app.py","startLine":42,"endLine":42,"startColumn":1,"message":"SQL injection via unsanitized user input","description":"Attacker can dump or modify the entire database.","fix":"Use a parameterized query: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"}]}

No vulnerabilities found:
{"issues":[]}

Field rules:
- ruleId: CWE number (CWE-89, CWE-78, CWE-79…) or OWASP code (A01:2021…); use "custom" if no standard applies
- severity: "error" for directly exploitable, high/critical impact; "warning" for likely vulnerable or requiring attacker-controlled conditions; "info" for defense-in-depth gaps
- category: must be one of: injection | authentication | authorization | cryptography | input-validation | deserialization | data-exposure | configuration | design
- message: single line, max 80 chars
- description: one sentence — what an attacker gains if this is exploited
- fix: one sentence — the specific code change to remediate`;

function buildFullScanPrompt(file: string, content: string, language: string, rules: SemgrepRule[]): string {
  const truncated = content.length > 8000 ? content.slice(0, 8000) + '\n\n[...file truncated...]' : content;
  const rulesSection = formatRulesSection(language, rules);
  // XML tags instead of backtick fences — backticks in source would break markdown fences
  // and create a prompt injection vector. XML closing tags are stripped from content as a precaution.
  const safeContent = truncated.replace(/<\/file_content>/gi, '');
  return `Scan this ${language} file for exploitable security issues. Apply the Semgrep rules below AND look beyond them — design decisions and insecure defaults that static rules cannot catch.${rulesSection}\nFile: ${file}\n<file_content>\n${safeContent}\n</file_content>`;
}

function buildDiffScanPrompt(file: string, content: string, diff: string, language: string, rules: SemgrepRule[]): string {
  const truncated = content.length > 8000 ? content.slice(0, 8000) + '\n\n[...truncated...]' : content;
  const truncatedDiff = diff.length > 4000 ? diff.slice(0, 4000) + '\n\n[...diff truncated...]' : diff;
  const rulesSection = formatRulesSection(language, rules);
  const safeContent = truncated.replace(/<\/file_content>/gi, '');
  const safeDiff = (truncatedDiff || '(no diff available)').replace(/<\/diff>/gi, '');
  return `Scan these ${language} changes for exploitable security issues introduced or exposed by this diff. Consider: what attack surface did this change open?${rulesSection}\nFile: ${file}\n\n<file_content>\n${safeContent}\n</file_content>\n\n<diff>\n${safeDiff}\n</diff>`;
}

// ---------------------------------------------------------------------------

// Binary file denylist — everything else is fair game for SAST scanning.
// This replaces the old extension allowlist so new languages never need a code change.
const BINARY_EXT_RE = /\.(png|jpe?g|gif|ico|webp|bmp|tiff?|mp4|m4v|avi|mov|wmv|webm|mp3|m4a|wav|flac|aac|ogg|wma|zip|tar|gz|bz2|xz|7z|rar|pdf|docx?|xlsx?|pptx?|pyc|class|o|a|so|dll|exe|bin|wasm|db|sqlite3?|jar|war|ear|dmg|pkg|deb|rpm|apk|ipa|xcarchive|ttf|otf|woff2?|eot)$/i;

// Repository control files — never code, nothing to scan.
const ALWAYS_SKIP_BASENAMES: ReadonlySet<string> = new Set(['.gitignore']);

// ---------------------------------------------------------------------------
// Language detection & Semgrep rules
// ---------------------------------------------------------------------------

// Maps file extension to the Semgrep language pack name used in the rules API.
// Unknown extensions map to 'generic' (no language-specific rules fetched).
const LANG_MAP: Record<string, string> = {
  '.py': 'python', '.pyw': 'python',
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.go': 'go',
  '.java': 'java',
  '.rb': 'ruby',
  '.rs': 'rust',
  '.php': 'php',
  '.c': 'c', '.h': 'c',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
  '.cs': 'csharp',
  '.swift': 'swift',
  '.kt': 'kotlin', '.kts': 'kotlin',
  '.scala': 'scala',
  '.sh': 'bash', '.bash': 'bash',
  '.tf': 'hcl', '.hcl': 'hcl',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.json': 'json',
  '.xml': 'xml',
  '.html': 'html', '.htm': 'html',
  '.dockerfile': 'dockerfile',
};

interface SemgrepRule {
  id: string;
  message: string;
  severity: string;
  cwe?: string[];
}

// In-memory rules cache: language → top rules. Populated on first scan per language.
const rulesCache = new Map<string, SemgrepRule[]>();

function detectLanguage(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  if (!ext && path.basename(filePath).toLowerCase() === 'dockerfile') { return 'dockerfile'; }
  return LANG_MAP[ext] ?? 'generic';
}

async function fetchRulesForLanguage(language: string): Promise<SemgrepRule[]> {
  if (language === 'generic' || language === 'json') { return []; }
  if (rulesCache.has(language)) { return rulesCache.get(language)!; }

  try {
    const response = await fetch(`https://semgrep.dev/c/p/${language}`, {
      signal: AbortSignal.timeout(15000),
      headers: { 'Accept': 'application/json' }
    });
    if (!response.ok) {
      outputChannel.appendLine(`  ⚠ Semgrep rules fetch failed for ${language}: HTTP ${response.status}`);
      // 404 = pack doesn't exist — cache permanently so we don't retry every scan.
      // Other HTTP errors (5xx, 429) are transient — don't cache so next scan retries.
      if (response.status === 404) { rulesCache.set(language, []); }
      return [];
    }

    const data = await response.json() as { rules?: any[] };
    const raw = data.rules ?? [];

    // Keep only security-category rules with at least MEDIUM confidence,
    // prioritising confirmed vulnerabilities (subcategory 'vuln') over audit hints.
    // Cap at 30 rules to keep prompt size sane.
    const rules: SemgrepRule[] = raw
      .filter((r: any) =>
        r.message &&
        r.metadata?.category === 'security' &&
        r.metadata?.confidence !== 'LOW'
      )
      .sort((a: any, b: any) => {
        const sevOrder: Record<string, number> = { ERROR: 0, WARNING: 1 };
        const subOrder = (r: any) => r.metadata?.subcategory?.includes('vuln') ? 0 : 1;
        const sevDiff = (sevOrder[a.severity] ?? 2) - (sevOrder[b.severity] ?? 2);
        return sevDiff !== 0 ? sevDiff : subOrder(a) - subOrder(b);
      })
      .slice(0, 30)
      .map((r: any) => ({
        id: r.id,
        // Trim to first sentence, max 100 chars to keep prompt compact
        message: (r.message.split(/\.\s/)[0] ?? r.message).trim().slice(0, 100),
        severity: r.severity,
        cwe: r.metadata?.cwe
      }));

    outputChannel.appendLine(`  📋 Loaded ${rules.length} Semgrep rules for ${language}`);
    rulesCache.set(language, rules);
    return rules;
  } catch (err: any) {
    outputChannel.appendLine(`  ⚠ Could not fetch Semgrep rules for ${language}: ${err.message}`);
    return [];  // don't cache — allow retry on next scan
  }
}

function formatRulesSection(language: string, rules: SemgrepRule[]): string {
  if (rules.length === 0) { return '\n'; }
  const lines = rules.map(r => `- ${r.id}: ${r.message}`).join('\n');
  return `\n\nLanguage: ${language}\nSemgrep security rules to apply (check each against the code):\n${lines}\n`;
}

// ---------------------------------------------------------------------------
// Concurrency helper — bounded worker pool, no external dependencies.
// Node.js is single-threaded so shared state (allIssues, scanCache) is safe.
// ---------------------------------------------------------------------------

async function runWithConcurrency<T>(
  items: T[],
  n: number,
  fn: (item: T, i: number) => Promise<void>
): Promise<void> {
  let cursor = 0;
  const worker = async () => {
    while (cursor < items.length) {
      const i = cursor++;
      await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
}

// ---------------------------------------------------------------------------
// SARIF report generation
// ---------------------------------------------------------------------------

function generateSarif(issues: any[], model: string, scanType: 'full' | 'changed'): object {
  const uniqueRuleIds = [...new Set(issues.map((i: any) => i.ruleId).filter(Boolean))];
  return {
    $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'AOYS',
          version: '0.1.0',
          informationUri: 'https://github.com/nickburnette-source/aoys',
          rules: uniqueRuleIds.map(id => ({
            id,
            shortDescription: { text: id },
            helpUri: id.startsWith('CWE-') ? `https://cwe.mitre.org/data/definitions/${id.replace('CWE-', '')}.html` : undefined
          }))
        }
      },
      properties: { model, scanType, timestamp: new Date().toISOString() },
      results: issues
        .filter((issue: any) => issue.file)  // skip issues without a resolvable file path
        .map((issue: any) => ({
        ...(issue.ruleId ? { ruleId: issue.ruleId } : {}),
        level: issue.severity === 'error' ? 'error' : issue.severity === 'warning' ? 'warning' : 'note',
        message: { text: issue.description ? `${issue.message} — ${issue.description}` : issue.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: issue.file.replace(/\\/g, '/') },
            region: {
              startLine: issue.startLine ?? 1,
              startColumn: issue.startColumn ?? 1,
              endLine: issue.endLine ?? issue.startLine ?? 1
            }
          }
        }]
      }))
    }]
  };
}

async function writeSarifReport(sarif: object, workspaceRoot: string): Promise<string | null> {
  try {
    const dir = path.join(workspaceRoot, '.aoys');
    await fs.promises.mkdir(dir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filePath = path.join(dir, `aoys-${stamp}.sarif`);
    await fs.promises.writeFile(filePath, JSON.stringify(sarif, null, 2), 'utf8');
    outputChannel.appendLine(`📄 SARIF report: ${filePath}`);
    return filePath;
  } catch (err: any) {
    outputChannel.appendLine(`  ⚠ Failed to write SARIF report: ${err.message}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Scan result cache — keyed by workspace-relative path, value = hash + issues.
// Skips the LLM call on full scans when file content hasn't changed.
// ---------------------------------------------------------------------------

interface ScanCacheEntry {
  hash: string;
  issues: any[];
  ts: string;
}

type ScanCache = Record<string, ScanCacheEntry>;

function hashContent(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
}

async function loadScanCache(workspaceRoot: string): Promise<ScanCache> {
  const cacheFile = path.join(workspaceRoot, '.aoys', 'scan-cache.json');
  try {
    const raw = await fs.promises.readFile(cacheFile, 'utf8');
    const parsed = JSON.parse(raw);
    return (typeof parsed === 'object' && parsed !== null) ? parsed as ScanCache : {};
  } catch {
    return {};
  }
}

async function saveScanCache(cache: ScanCache, workspaceRoot: string, scannedFiles: string[]): Promise<void> {
  // Prune entries for files not in this scan (deleted or excluded files).
  const scannedSet = new Set(scannedFiles);
  const pruned: ScanCache = {};
  for (const [k, v] of Object.entries(cache)) {
    if (scannedSet.has(k)) { pruned[k] = v; }
  }
  const dir = path.join(workspaceRoot, '.aoys');
  const cacheFile = path.join(dir, 'scan-cache.json');
  try {
    await fs.promises.mkdir(dir, { recursive: true });
    await fs.promises.writeFile(cacheFile, JSON.stringify(pruned, null, 2), 'utf8');
  } catch (err: any) {
    outputChannel.appendLine(`  ⚠ Failed to save scan cache: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// .aoysignore support
// ---------------------------------------------------------------------------

// Read .aoys/.aoysignore for user-defined exclusion patterns (gitignore syntax).
// Returns an empty array if the file doesn't exist — that's the normal case.
function loadAoysIgnorePatterns(workspaceRoot: string): string[] {
  const ignorePath = path.join(workspaceRoot, '.aoys', '.aoysignore');
  try {
    return fs.readFileSync(ignorePath, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && !l.startsWith('!')); // skip comments + unsupported negations
  } catch {
    return [];
  }
}

// Returns true if relPath should be excluded from scanning.
function shouldSkipFile(relPath: string, aoysIgnorePatterns: string[]): boolean {
  if (ALWAYS_SKIP_BASENAMES.has(path.basename(relPath))) { return true; }
  const normalPath = relPath.replace(/\\/g, '/');
  if (normalPath.startsWith('.aoys/')) { return true; } // always skip internal extension dir
  return aoysIgnorePatterns.some(p => gitignorePatternMatches(normalPath, p));
}

// Matches a workspace-relative POSIX path against a single gitignore-style pattern.
// Supports: * ? ** anchored (/prefix) and directory (suffix/) patterns.
// Negation (!) is intentionally unsupported — strip those in the caller.
function gitignorePatternMatches(normalPath: string, pattern: string): boolean {
  let pat = pattern;
  const rooted = pat.startsWith('/');
  if (rooted) { pat = pat.slice(1); }
  const dirOnly = pat.endsWith('/');
  if (dirOnly) { pat = pat.slice(0, -1); }
  if (!pat) { return false; }

  // Build regexStr in a single character-by-character pass.
  // Chained .replace() calls corrupt each other: the * quantifier in previously
  // inserted (?:[^/]+/)* gets hit by the later * → [^/]* replacement, breaking
  // all ** patterns. One-pass parsing is the correct fix.
  let regexStr = '';
  let i = 0;
  while (i < pat.length) {
    const ch = pat[i];
    if (ch === '*') {
      if (pat[i + 1] === '*') {
        if (pat[i + 2] === '/') {
          regexStr += '(?:[^/]+/)*'; // **/ → zero-or-more path segments
          i += 3;
        } else {
          regexStr += '.*';          // ** → anything
          i += 2;
        }
      } else {
        regexStr += '[^/]*';         // * → within-segment wildcard
        i += 1;
      }
    } else if (ch === '?') {
      regexStr += '[^/]';
      i += 1;
    } else if (/[.+^${}()|[\]\\]/.test(ch)) {
      regexStr += '\\' + ch;        // escape regex specials
      i += 1;
    } else {
      regexStr += ch;
      i += 1;
    }
  }

  try {
    if (dirOnly) {
      const anchor = rooted || pat.includes('/') ? '^' : '(?:^|/)';
      return new RegExp(`${anchor}${regexStr}/`).test(normalPath);
    } else if (rooted || pat.includes('/')) {
      return new RegExp(`^${regexStr}$`).test(normalPath);
    } else {
      return new RegExp(`(?:^|/)${regexStr}$`).test(normalPath);
    }
  } catch {
    return false; // invalid pattern in .aoysignore — skip silently
  }
}

interface AuditConfig {
  baseUrl: string;
  model: string;
  temperature: number;
}

interface SSEChunk {
  choices?: Array<{
    delta?: {
      content?: string;
      reasoning_content?: string; // Ollama 0.6+ thinking models
    };
  }>;
}

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let scanInProgress = false;
let modelCache: { baseUrl: string; model: string } | null = null;

export function activate(context: vscode.ExtensionContext) {
  console.log('✅ AOYS activated');

  diagnosticCollection = vscode.languages.createDiagnosticCollection('aoys');
  context.subscriptions.push(diagnosticCollection);

  outputChannel = vscode.window.createOutputChannel('AOYS');
  context.subscriptions.push(outputChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand('aoys.scanChanged', () => withScanLock(scanChangedFiles)),
    vscode.commands.registerCommand('aoys.scanFullProject', () => withScanLock(scanFullProject)),
    vscode.commands.registerCommand('aoys.selectModel', selectModel),
    vscode.commands.registerCommand('aoys.showOutput', () => outputChannel.show())
  );

  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.text = '$(shield) AOYS';
  statusBar.command = 'aoys.scanChanged';
  const tooltip = new vscode.MarkdownString(
    '**AOYS**\n\n$(play) Click to scan changed files\n\n[Select Model](command:aoys.selectModel) · [Full Scan](command:aoys.scanFullProject) · [Show Output](command:aoys.showOutput)',
    true
  );
  tooltip.isTrusted = true;
  statusBar.tooltip = tooltip;
  statusBar.show();
  context.subscriptions.push(statusBar);

  if (!context.globalState.get('initialScanPrompted')) {
    context.globalState.update('initialScanPrompted', true);
    vscode.window.showInformationMessage(
      'AOYS is ready. Run a full project scan now? (Configure aoys.baseUrl / aoys.model in Settings first if needed)',
      'Scan Now',
      'Later'
    ).then(choice => {
      if (choice === 'Scan Now') {
        vscode.commands.executeCommand('aoys.scanFullProject');
      }
    });
  }
}

async function withScanLock(fn: () => Promise<void>): Promise<void> {
  if (scanInProgress) {
    vscode.window.showWarningMessage('AOYS: A scan is already in progress.');
    return;
  }
  scanInProgress = true;
  try {
    await fn();
  } finally {
    scanInProgress = false;
  }
}

async function getConfig(): Promise<AuditConfig | null> {
  const config = vscode.workspace.getConfiguration('aoys');
  const baseUrl = config.get<string>('baseUrl');
  const configuredModel = config.get<string>('model');
  const temperature = config.get<number>('temperature');

  if (!baseUrl || !configuredModel || temperature === undefined || temperature === null) {
    vscode.window.showErrorMessage(
      'AOYS: Missing configuration. Please set aoys.baseUrl, aoys.model, and aoys.temperature in Settings.'
    );
    return null;
  }

  const resolvedBaseUrl = baseUrl.replace(/\/$/, '');
  const model = await resolveModel(resolvedBaseUrl, configuredModel);
  if (!model) { return null; }

  return { baseUrl: resolvedBaseUrl, model, temperature };
}

async function resolveModel(baseUrl: string, configured: string): Promise<string | null> {
  if (configured !== 'auto') { return configured; }
  if (modelCache && modelCache.baseUrl === baseUrl) { return modelCache.model; }

  const detected = await detectBestGemmaModel(baseUrl);
  if (!detected) {
    vscode.window.showErrorMessage(
      `AOYS: No Gemma models found at ${baseUrl}. Install one with: ollama pull gemma4`
    );
    return null;
  }

  modelCache = { baseUrl, model: detected };
  return detected;
}

async function detectBestGemmaModel(baseUrl: string): Promise<string | null> {
  try {
    const response = await fetch(`${baseUrl}/models`);
    if (!response.ok) { return null; }
    const data = await response.json() as { data?: Array<{ id: string }> };
    const gemmaModels = (data.data ?? [])
      .map(m => m.id)
      .filter(id => /^gemma/i.test(id));

    if (gemmaModels.length === 0) { return null; }

    gemmaModels.sort((a, b) => scoreGemmaModel(b) - scoreGemmaModel(a));
    return gemmaModels[0];
  } catch {
    return null;
  }
}

function scoreGemmaModel(id: string): number {
  // Score by Gemma version (gemma4 > gemma3 > gemma2 > gemma) then by param count (31b > 27b > 9b…)
  const versionMatch = id.match(/^gemma(\d+)?/i);
  const version = versionMatch?.[1] ? parseInt(versionMatch[1]) : 1;
  const sizeMatch = id.match(/:(\d+(?:\.\d+)?)b/i);
  const params = sizeMatch ? parseFloat(sizeMatch[1]) : 0;
  return version * 1000 + params;
}

function getWorkspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

async function selectModel(): Promise<void> {
  const config = vscode.workspace.getConfiguration('aoys');
  const baseUrl = (config.get<string>('baseUrl') ?? 'http://localhost:11434/v1').replace(/\/$/, '');
  const currentModel = config.get<string>('model') ?? 'auto';

  let modelIds: string[] = [];
  try {
    const response = await fetch(`${baseUrl}/models`);
    if (!response.ok) { throw new Error(`HTTP ${response.status}`); }
    const data = await response.json() as { data?: Array<{ id: string }> };
    modelIds = (data.data ?? []).map(m => m.id).sort();
  } catch (err: any) {
    vscode.window.showErrorMessage(`AOYS: Could not list models from ${baseUrl}: ${err.message}. Check aoys.baseUrl in Settings.`);
    return;
  }

  if (modelIds.length === 0) {
    vscode.window.showErrorMessage(`AOYS: No models found at ${baseUrl}.`);
    return;
  }

  const resolvedAuto = modelCache?.baseUrl === baseUrl ? modelCache.model : undefined;

  const items: vscode.QuickPickItem[] = [
    {
      label: 'auto',
      description: 'Best available Gemma model (auto-detected)',
      detail: resolvedAuto ? `Currently resolves to: ${resolvedAuto}` : undefined,
      picked: currentModel === 'auto'
    },
    ...modelIds.map(id => ({
      label: id,
      picked: id === currentModel
    }))
  ];

  const picked = await vscode.window.showQuickPick(items, {
    title: 'AOYS: Select Model',
    placeHolder: 'Choose which model to use for code auditing'
  });

  if (!picked) { return; }

  await config.update('model', picked.label, vscode.ConfigurationTarget.Global);
  modelCache = null; // always invalidate so next scan re-detects with current model list
  vscode.window.showInformationMessage(`AOYS: Model set to "${picked.label}"`);
}

async function scanChangedFiles(): Promise<void> {
  const workspaceRoot = getWorkspaceRoot();
  if (!workspaceRoot) {
    vscode.window.showErrorMessage('AOYS: No workspace folder open');
    return;
  }

  const config = await getConfig();
  if (!config) { return; }

  let files: string[];
  try {
    const git = simpleGit(workspaceRoot);
    const status = await git.status();
    const renamed = status.renamed.map(r => r.to);
    files = [...new Set([...status.staged, ...status.modified, ...status.created, ...renamed])]
      .filter(f => !BINARY_EXT_RE.test(f));
  } catch (err: any) {
    vscode.window.showErrorMessage(`AOYS: Failed to read git status: ${err.message}`);
    return;
  }

  const aoysIgnorePatterns = loadAoysIgnorePatterns(workspaceRoot);
  const preFilterCount = files.length;
  files = files.filter(f => !shouldSkipFile(f, aoysIgnorePatterns));

  if (files.length === 0) {
    vscode.window.showInformationMessage('AOYS: No changed files to scan');
    return;
  }

  const excludedNote = preFilterCount > files.length ? ` · ${preFilterCount - files.length} excluded` : '';
  outputChannel.show(true);
  outputChannel.appendLine(`\n${'─'.repeat(60)}`);
  outputChannel.appendLine(`AOYS Scan · ${config.model} · ${new Date().toLocaleTimeString()}`);
  outputChannel.appendLine(`Scanning ${files.length} changed file(s)${excludedNote}`);
  outputChannel.appendLine('─'.repeat(60));

  // Prefetch Semgrep rules for all detected languages before the scan loop.
  const uniqueLangs = new Set(files.map(f => detectLanguage(f)).filter(l => l !== 'generic'));
  if (uniqueLangs.size > 0) {
    outputChannel.appendLine(`Fetching Semgrep rules for: ${[...uniqueLangs].join(', ')}`);
    await Promise.all([...uniqueLangs].map(lang => fetchRulesForLanguage(lang)));
  }

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `AOYS (${config.model})`, cancellable: true },
    async (progress, token) => {
      const git = simpleGit(workspaceRoot);
      const allIssues: any[] = [];

      const concurrency = vscode.workspace.getConfiguration('aoys').get<number>('scanConcurrency') ?? 3;
      await runWithConcurrency(files, concurrency, async (file, i) => {
        if (token.isCancellationRequested) { return; }

        const prefix = `${i + 1}/${files.length}`;
        const language = detectLanguage(file);
        const rules = rulesCache.get(language) ?? [];

        // Print header immediately so the output shows which files are in-flight.
        outputChannel.appendLine(`\n[${prefix}] ${file} (${language}${rules.length > 0 ? `, ${rules.length} rules` : ''})`);

        const t0 = Date.now();
        let thoughtAccum = '';
        let lastThoughtTs = 0;
        try {
          const document = await vscode.workspace.openTextDocument(path.join(workspaceRoot, file));
          const diff = await git.diff([file]);
          const issues = await auditFile(config, file, buildDiffScanPrompt(file, document.getText(), diff, language, rules), token, (delta) => {
            // Accumulate raw SSE deltas; emit at most every 3s to avoid flooding.
            thoughtAccum += delta;
            const now = Date.now();
            if (now - lastThoughtTs >= 3000) {
              lastThoughtTs = now;
              const snippet = thoughtAccum.replace(/\n/g, ' ').trim().slice(0, 100);
              if (snippet) { outputChannel.appendLine(`[${prefix}]     💭 ${snippet}`); }
            }
          }, prefix);
          allIssues.push(...issues);
          const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
          outputChannel.appendLine(`[${prefix}]     ✓ ${issues.length} issue(s) · ${elapsed}s`);
          issues.forEach(iss => outputChannel.appendLine(`[${prefix}]       [${iss.severity}] ${iss.message} (line ${iss.startLine})`));
          progress.report({ increment: 100 / files.length });
        } catch (err: any) {
          const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
          outputChannel.appendLine(`[${prefix}]     ✗ skipped: ${err.message} (${elapsed}s)`);
          console.error(`AOYS: Error processing ${file}:`, err);
          vscode.window.showWarningMessage(`AOYS: Skipped ${file}: ${err.message}`);
          progress.report({ increment: 100 / files.length });
        }
      });

      outputChannel.appendLine(`\n${'─'.repeat(60)}`);
      outputChannel.appendLine(`Done · ${allIssues.length} total issue(s)`);
      applyDiagnostics(allIssues, workspaceRoot);
      const sarif = generateSarif(allIssues, config.model, 'changed');
      const sarifPath = await writeSarifReport(sarif, workspaceRoot);
      reportResults(allIssues, sarifPath);
    }
  );
}

async function scanFullProject(): Promise<void> {
  const workspaceRoot = getWorkspaceRoot();
  if (!workspaceRoot) {
    vscode.window.showErrorMessage('AOYS: No workspace folder open');
    return;
  }

  const config = await getConfig();
  if (!config) { return; }

  let uris: vscode.Uri[];
  try {
    // Use git ls-files so .gitignore is respected automatically.
    // Falls back to workspace.findFiles for non-git repos.
    const git = simpleGit(workspaceRoot);
    const result = await git.raw(['ls-files', '--cached', '--others', '--exclude-standard']);
    const filePaths = result.trim().split('\n')
      .filter(f => f.length > 0 && !BINARY_EXT_RE.test(f));
    uris = filePaths.map(f => vscode.Uri.file(path.join(workspaceRoot, f)));
  } catch {
    try {
      const found = await vscode.workspace.findFiles('**/*', '{**/node_modules/**,**/dist/**,**/.git/**}');
      uris = found.filter(u => !BINARY_EXT_RE.test(u.fsPath));
    } catch (err: any) {
      vscode.window.showErrorMessage(`AOYS: Failed to enumerate project files: ${err.message}`);
      return;
    }
  }

  if (uris.length === 0) {
    vscode.window.showInformationMessage('AOYS: No supported files found in project');
    return;
  }

  const aoysIgnorePatterns = loadAoysIgnorePatterns(workspaceRoot);
  const preFilterCount = uris.length;
  uris = uris.filter(u => !shouldSkipFile(path.relative(workspaceRoot, u.fsPath), aoysIgnorePatterns));

  const concurrency = vscode.workspace.getConfiguration('aoys').get<number>('scanConcurrency') ?? 3;
  const relFiles = uris.map(u => path.relative(workspaceRoot, u.fsPath));

  outputChannel.show(true);
  outputChannel.appendLine(`\n${'─'.repeat(60)}`);
  outputChannel.appendLine(`AOYS Full Scan · ${config.model} · ${new Date().toLocaleTimeString()}`);
  const excludedNote = preFilterCount > uris.length ? ` · ${preFilterCount - uris.length} excluded` : '';
  outputChannel.appendLine(`${uris.length} file(s) to scan${excludedNote} · ${concurrency} concurrent`);
  outputChannel.appendLine('─'.repeat(60));

  // Detect all languages upfront and prefetch their Semgrep rules in parallel.
  // Cache is populated here so per-file lookups are instant.
  const uniqueLangs = new Set(uris.map(u => detectLanguage(u.fsPath)).filter(l => l !== 'generic'));
  if (uniqueLangs.size > 0) {
    outputChannel.appendLine(`Fetching Semgrep rules for: ${[...uniqueLangs].join(', ')}`);
    await Promise.all([...uniqueLangs].map(lang => fetchRulesForLanguage(lang)));
  }

  const scanCache = await loadScanCache(workspaceRoot);

  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `AOYS Full Scan (${config.model})`, cancellable: true },
    async (progress, token) => {
      const allIssues: any[] = [];
      let cancelPrinted = false;

      await runWithConcurrency(relFiles, concurrency, async (relFile, i) => {
        if (token.isCancellationRequested) {
          if (!cancelPrinted) { cancelPrinted = true; outputChannel.appendLine('\n⚠ Scan cancelled by user.'); }
          return;
        }

        const uri = uris[i];
        const prefix = `${i + 1}/${relFiles.length}`;
        const language = detectLanguage(uri.fsPath);
        const rules = rulesCache.get(language) ?? [];
        // Print header immediately so the output shows which files are in-flight.
        outputChannel.appendLine(`\n[${prefix}] ${relFile} (${language}${rules.length > 0 ? `, ${rules.length} rules` : ''})`);

        // Check cache before opening the file — fast path for unchanged files.
        let document: vscode.TextDocument;
        try {
          document = await vscode.workspace.openTextDocument(uri);
        } catch (err: any) {
          outputChannel.appendLine(`[${prefix}]     ✗ skipped: ${err.message}`);
          progress.report({ increment: 100 / relFiles.length });
          return;
        }

        const content = document.getText();
        const hash = hashContent(content);
        const cached = scanCache[relFile];
        if (cached && cached.hash === hash) {
          allIssues.push(...cached.issues);
          outputChannel.appendLine(`[${prefix}]     [cached] ${cached.issues.length} issue(s)`);
          progress.report({ increment: 100 / relFiles.length });
          return;
        }

        const t0 = Date.now();
        let thoughtAccum = '';
        let lastThoughtTs = 0;
        try {
          const issues = await auditFile(config, relFile, buildFullScanPrompt(relFile, content, language, rules), token, (delta) => {
            // Accumulate raw SSE deltas; emit at most every 3s to avoid flooding.
            thoughtAccum += delta;
            const now = Date.now();
            if (now - lastThoughtTs >= 3000) {
              lastThoughtTs = now;
              const snippet = thoughtAccum.replace(/\n/g, ' ').trim().slice(0, 100);
              if (snippet) { outputChannel.appendLine(`[${prefix}]     💭 ${snippet}`); }
            }
          }, prefix);
          allIssues.push(...issues);
          scanCache[relFile] = { hash, issues, ts: new Date().toISOString() };
          const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
          outputChannel.appendLine(`[${prefix}]     ✓ ${issues.length} issue(s) · ${elapsed}s`);
          issues.forEach(iss => outputChannel.appendLine(`[${prefix}]       [${iss.severity}] ${iss.message} (line ${iss.startLine})`));
          progress.report({ increment: 100 / relFiles.length });
        } catch (err: any) {
          const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
          outputChannel.appendLine(`[${prefix}]     ✗ skipped: ${err.message} (${elapsed}s)`);
          console.error(`AOYS: Error processing ${relFile}:`, err);
          vscode.window.showWarningMessage(`AOYS: Skipped ${relFile}: ${err.message}`);
          progress.report({ increment: 100 / relFiles.length });
        }
      });

      outputChannel.appendLine(`\n${'─'.repeat(60)}`);
      outputChannel.appendLine(`Done · ${allIssues.length} total issue(s) · ${new Date().toLocaleTimeString()}`);
      applyDiagnostics(allIssues, workspaceRoot);
      const sarif = generateSarif(allIssues, config.model, 'full');
      const sarifPath = await writeSarifReport(sarif, workspaceRoot);
      reportResults(allIssues, sarifPath);
    }
  );

  await saveScanCache(scanCache, workspaceRoot, relFiles);
}

async function auditFile(config: AuditConfig, _file: string, userPrompt: string, cancelToken?: vscode.CancellationToken, onThinking?: (text: string) => void, logPrefix?: string): Promise<any[]> {
  const controller = new AbortController();
  const cancelSub = cancelToken?.onCancellationRequested(() => controller.abort());
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;

  try {
    const response = await fetch(`${config.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        model: config.model,
        temperature: config.temperature,
        stream: true,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userPrompt }
        ],
        response_format: { type: 'json_object' }
      })
    });

    if (!response.ok) { throw new Error(`HTTP ${response.status}`); }
    if (!response.body) { throw new Error('No response body from server'); }

    // Stream SSE chunks — keeps the TCP connection alive so long-running
    // inference on large files doesn't hit the headers timeout.
    reader = response.body.getReader();
    const decoder = new TextDecoder();
    let sseBuffer = '';
    let content = '';

    const handleChunk = (chunk: SSEChunk) => {
      const delta = chunk.choices?.[0]?.delta;
      if (delta?.reasoning_content) { onThinking?.(delta.reasoning_content); }
      if (delta?.content) { content += delta.content; }
    };

    streamLoop: while (true) {
      const { done, value } = await reader.read();
      if (done) { break; }
      sseBuffer += decoder.decode(value, { stream: true });
      const lines = sseBuffer.split('\n');
      sseBuffer = lines.pop() ?? '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data:')) { continue; }
        const data = trimmed.slice(5).trimStart(); // accept both 'data: ' and 'data:'
        if (data === '[DONE]') { break streamLoop; }
        try { handleChunk(JSON.parse(data) as SSEChunk); } catch { /* ignore malformed SSE frames */ }
      }
    }

    // Flush TextDecoder's internal buffer and process any trailing SSE line
    // that didn't end with '\n' before the stream closed.
    sseBuffer += decoder.decode();
    const tail = sseBuffer.trim();
    if (tail.startsWith('data:')) {
      const data = tail.slice(5).trimStart();
      if (data && data !== '[DONE]') {
        try { handleChunk(JSON.parse(data) as SSEChunk); } catch { /* ignore */ }
      }
    }

    // Strip <think>...</think> blocks — some Ollama versions embed thinking
    // directly in content rather than in reasoning_content.
    const cleanContent = content.replace(/<think>[\s\S]*?<\/think>/g, '').trim();

    let parsed: any;
    try {
      parsed = JSON.parse(cleanContent || '{}');
    } catch {
      outputChannel.appendLine(`${logPrefix ? `[${logPrefix}] ` : ''}    ⚠ Invalid JSON from model — raw: ${cleanContent.slice(0, 200)}`);
      return [];
    }
    return Array.isArray(parsed.issues) ? sanitizeIssues(parsed.issues) : [];
  } catch (err: any) {
    const cause = err.cause?.message ?? err.cause?.code ?? '';
    const msg = err.name === 'AbortError'
      ? 'cancelled by user'
      : cause ? `${err.message} (${cause})` : err.message;
    outputChannel.appendLine(`${logPrefix ? `[${logPrefix}] ` : ''}    ✗ auditFile error: ${msg}`);
    throw new Error(msg);
  } finally {
    try { await reader?.cancel(); } catch { /* cleanup */ }
    cancelSub?.dispose();
  }
}

function reportResults(issues: any[], sarifPath?: string | null): void {
  if (issues.length > 0) {
    const msg = `AOYS found ${issues.length} issue(s). Check the Problems panel.`;
    if (sarifPath) {
      vscode.window.showInformationMessage(msg, 'Open Report').then(choice => {
        if (choice === 'Open Report') {
          (async () => {
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(sarifPath));
            await vscode.window.showTextDocument(doc);
          })().catch((err: Error) => vscode.window.showErrorMessage(`Could not open SARIF report: ${err.message}`));
        }
      });
    } else {
      vscode.window.showInformationMessage(msg);
    }
  } else {
    vscode.window.showInformationMessage('AOYS scan complete — no issues found 🎉');
  }
}

function sanitizeIssues(raw: any[]): any[] {
  return raw
    .filter(issue => issue && typeof issue.message === 'string' && issue.message.trim() &&
                     typeof issue.file === 'string' && issue.file.trim())
    .map(issue => ({
      ...issue,
      message: String(issue.message).slice(0, 200),
      description: typeof issue.description === 'string' ? issue.description : undefined,
      fix: typeof issue.fix === 'string' ? issue.fix : undefined,
      severity: ['error', 'warning', 'info'].includes(issue.severity) ? issue.severity : 'warning',
      category: typeof issue.category === 'string' ? issue.category : 'configuration',
      ruleId: typeof issue.ruleId === 'string' ? issue.ruleId : undefined,
      startLine: typeof issue.startLine === 'number' && isFinite(issue.startLine) ? issue.startLine : 1,
      endLine: typeof issue.endLine === 'number' && isFinite(issue.endLine) ? issue.endLine : (issue.startLine ?? 1),
      startColumn: typeof issue.startColumn === 'number' && isFinite(issue.startColumn) ? issue.startColumn : 1,
    }));
}

function safePos(line: unknown, col: unknown): vscode.Position {
  const l = (typeof line === 'number' && isFinite(line) && line >= 1) ? Math.floor(line) - 1 : 0;
  const c = (typeof col === 'number' && isFinite(col) && col >= 1) ? Math.floor(col) - 1 : 0;
  return new vscode.Position(l, c);
}

function applyDiagnostics(issues: any[], workspaceRoot: string): void {
  diagnosticCollection.clear();
  const diagnosticsMap = new Map<string, vscode.Diagnostic[]>();

  for (const issue of issues) {
    if (!issue.file || typeof issue.file !== 'string') { continue; }

    const absFile = path.resolve(workspaceRoot, issue.file);
    // Reject any path that escapes the workspace root — LLM output is untrusted.
    if (!absFile.startsWith(workspaceRoot + path.sep) && absFile !== workspaceRoot) { continue; }
    if (!diagnosticsMap.has(absFile)) { diagnosticsMap.set(absFile, []); }

    const start = safePos(issue.startLine, issue.startColumn);
    const end = safePos(issue.endLine ?? issue.startLine, 0);
    const range = new vscode.Range(start, new vscode.Position(end.line, 1000));

    const diag = new vscode.Diagnostic(
      range,
      `${issue.message} — ${issue.description}`,
      issue.severity === 'error' ? vscode.DiagnosticSeverity.Error :
      issue.severity === 'warning' ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information
    );
    diag.code = issue.ruleId;
    diag.source = 'AOYS';
    diagnosticsMap.get(absFile)!.push(diag);
  }

  for (const [absFile, diags] of diagnosticsMap) {
    diagnosticCollection.set(vscode.Uri.file(absFile), diags);
  }
}

export function deactivate() {}
