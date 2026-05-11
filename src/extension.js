"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
var vscode = require("vscode");
var simple_git_1 = require("simple-git");
var GEMMA4_AUDITOR_PROMPT = "You are Gemma4-Code-Auditor, an elite autonomous code security and quality analysis engine.\n\nYour mission: find EVERY possible defect in the provided code \u2014 security vulnerabilities (OWASP, CWE, injection, auth bypass, crypto misuse, etc.), functional bugs, performance & scalability issues, maintainability smells, architectural problems, deprecated APIs, anti-patterns, error-handling gaps, and anything else that can be improved.\n\nBe extremely thorough, critical, and precise. Focus first on the changed sections in the git diff while considering the full file context.\n\nRespond with NOTHING but valid JSON matching this exact schema:\n\n{\n  \"issues\": [\n    {\n      \"ruleId\": \"string\",\n      \"severity\": \"error\" | \"warning\" | \"info\",\n      \"category\": \"security\" | \"bug\" | \"performance\" | \"maintainability\" | \"style\" | \"deprecated\" | \"architecture\" | \"other\",\n      \"file\": \"string\",\n      \"startLine\": number,\n      \"endLine\": number,\n      \"startColumn\": number,\n      \"message\": \"short clear title\",\n      \"description\": \"detailed explanation with impact\",\n      \"fix\": {\n        \"description\": \"brief fix explanation\",\n        \"patch\": \"valid unified diff patch (--- +++ @@ format) OR null if no safe auto-fix\"\n      } | null\n    }\n  ]\n}\n\nOnly output the JSON. No explanations, no markdown, no extra text.";
var diagnosticCollection;
function activate(context) {
    var _this = this;
    console.log('✅ AOYS (Gemma 4) activated');
    diagnosticCollection = vscode.languages.createDiagnosticCollection('aoys');
    context.subscriptions.push(diagnosticCollection);
    var scanChanged = vscode.commands.registerCommand('aoys.scanChanged', function () { return __awaiter(_this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, scanFiles(true)];
                case 1:
                    _a.sent();
                    return [2 /*return*/];
            }
        });
    }); });
    var scanFull = vscode.commands.registerCommand('aoys.scanFullProject', function () { return __awaiter(_this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            vscode.window.showInformationMessage('Full project scan coming in next iteration');
            return [2 /*return*/];
        });
    }); });
    context.subscriptions.push(scanChanged, scanFull);
    var statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBar.text = "$(shield) AOYS";
    statusBar.command = 'aoys.scanChanged';
    statusBar.tooltip = 'Click to scan changed files with Gemma 4';
    statusBar.show();
    context.subscriptions.push(statusBar);
}
function scanFiles(incremental) {
    return __awaiter(this, void 0, void 0, function () {
        var config, baseUrl, model, temperature, workspaceRoot, git, filesToScan, status_1, issues, _i, filesToScan_1, file, fullPath, document_1, content, diff, userPrompt, response, data, contentStr, json, err_1;
        var _a, _b, _c, _d, _e;
        return __generator(this, function (_f) {
            switch (_f.label) {
                case 0:
                    config = vscode.workspace.getConfiguration('aoys');
                    baseUrl = config.get('baseUrl').replace(/\/$/, '');
                    model = config.get('model');
                    temperature = config.get('temperature');
                    workspaceRoot = (_b = (_a = vscode.workspace.workspaceFolders) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.uri.fsPath;
                    if (!workspaceRoot) {
                        vscode.window.showErrorMessage('No workspace folder open');
                        return [2 /*return*/];
                    }
                    git = (0, simple_git_1.default)(workspaceRoot);
                    filesToScan = [];
                    if (!incremental) return [3 /*break*/, 2];
                    return [4 /*yield*/, git.status()];
                case 1:
                    status_1 = _f.sent();
                    filesToScan = __spreadArray(__spreadArray(__spreadArray([], status_1.staged, true), status_1.modified, true), status_1.created, true).filter(function (f) { return /\.(ts|js|py|go|java|cpp|cs|php|rb|rs|swift|kt)$/.test(f); });
                    if (filesToScan.length === 0) {
                        vscode.window.showInformationMessage('No changed files to scan');
                        return [2 /*return*/];
                    }
                    vscode.window.showInformationMessage("AOYS scanning ".concat(filesToScan.length, " changed file(s)..."));
                    return [3 /*break*/, 3];
                case 2: return [2 /*return*/];
                case 3:
                    issues = [];
                    _i = 0, filesToScan_1 = filesToScan;
                    _f.label = 4;
                case 4:
                    if (!(_i < filesToScan_1.length)) return [3 /*break*/, 12];
                    file = filesToScan_1[_i];
                    fullPath = "".concat(workspaceRoot, "/").concat(file);
                    return [4 /*yield*/, vscode.workspace.openTextDocument(fullPath)];
                case 5:
                    document_1 = _f.sent();
                    content = document_1.getText();
                    return [4 /*yield*/, git.diff([file])];
                case 6:
                    diff = _f.sent();
                    userPrompt = "File: ".concat(file, "\n\nFull content:\n").concat(content, "\n\nGit diff:\n").concat(diff || '(no diff available)', "\n\nAnalyze now.");
                    _f.label = 7;
                case 7:
                    _f.trys.push([7, 10, , 11]);
                    return [4 /*yield*/, fetch("".concat(baseUrl, "/chat/completions"), {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                model: model,
                                temperature: temperature,
                                max_tokens: 4000,
                                messages: [
                                    { role: 'system', content: GEMMA4_AUDITOR_PROMPT },
                                    { role: 'user', content: userPrompt }
                                ],
                                response_format: { type: 'json_object' }
                            })
                        })];
                case 8:
                    response = _f.sent();
                    if (!response.ok)
                        throw new Error("HTTP ".concat(response.status));
                    return [4 /*yield*/, response.json()];
                case 9:
                    data = _f.sent();
                    contentStr = ((_e = (_d = (_c = data.choices) === null || _c === void 0 ? void 0 : _c[0]) === null || _d === void 0 ? void 0 : _d.message) === null || _e === void 0 ? void 0 : _e.content) || '{}';
                    json = JSON.parse(contentStr);
                    if (json.issues && Array.isArray(json.issues)) {
                        issues.push.apply(issues, json.issues);
                    }
                    return [3 /*break*/, 11];
                case 10:
                    err_1 = _f.sent();
                    console.error("Error scanning ".concat(file, ":"), err_1);
                    vscode.window.showWarningMessage("AOYS failed to scan ".concat(file, ": ").concat(err_1.message));
                    return [3 /*break*/, 11];
                case 11:
                    _i++;
                    return [3 /*break*/, 4];
                case 12:
                    applyDiagnostics(issues);
                    if (issues.length > 0) {
                        vscode.window.showInformationMessage("AOYS found ".concat(issues.length, " issue(s). Check the Problems panel."));
                    }
                    else {
                        vscode.window.showInformationMessage('AOYS scan complete — no issues found 🎉');
                    }
                    return [2 /*return*/];
            }
        });
    });
}
function applyDiagnostics(issues) {
    diagnosticCollection.clear();
    var diagnosticsMap = new Map();
    for (var _i = 0, issues_1 = issues; _i < issues_1.length; _i++) {
        var issue = issues_1[_i];
        var uri = vscode.Uri.file(issue.file || '');
        if (!diagnosticsMap.has(issue.file))
            diagnosticsMap.set(issue.file, []);
        var range = new vscode.Range(new vscode.Position((issue.startLine || 1) - 1, (issue.startColumn || 1) - 1), new vscode.Position(((issue.endLine || issue.startLine) || 1) - 1, 1000));
        var diag = new vscode.Diagnostic(range, "".concat(issue.message, " \u2014 ").concat(issue.description), issue.severity === 'error' ? vscode.DiagnosticSeverity.Error :
            issue.severity === 'warning' ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information);
        diag.code = issue.ruleId;
        diag.source = 'AOYS (Gemma 4)';
        diagnosticsMap.get(issue.file).push(diag);
    }
    for (var _a = 0, diagnosticsMap_1 = diagnosticsMap; _a < diagnosticsMap_1.length; _a++) {
        var _b = diagnosticsMap_1[_a], file = _b[0], diags = _b[1];
        diagnosticCollection.set(vscode.Uri.file(file), diags);
    }
}
function deactivate() { }
