import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";

import { WeedoutApi } from "./api";
import { dependencyKey, findDependencyOccurrences, inlineHint, isManifest, MANIFEST_PATTERNS, manifestRank } from "./manifest";
import type { DependencyOccurrence, Finding, ProjectBinding } from "./types";

const MACHINE_TOKEN = "weedout.machineToken";
const BINDING = "weedout.projectBinding";
const EXCLUDES = "**/{node_modules,.git,dist,build,.idea,.venv,vendor}/**";

function api(): WeedoutApi {
  const value = vscode.workspace.getConfiguration("weedout").get<string>("serverUrl", "https://weedout.dev");
  return new WeedoutApi(value);
}

function projectSecret(binding: ProjectBinding): string {
  return `weedout.projectKey:${binding.workspace}:${binding.id}`;
}

class FindingTree implements vscode.TreeDataProvider<Finding> {
  private findings: Finding[] = [];
  private readonly changed = new vscode.EventEmitter<Finding | undefined>();
  readonly onDidChangeTreeData = this.changed.event;

  update(findings: Finding[]) {
    this.findings = findings;
    this.changed.fire(undefined);
  }

  getTreeItem(finding: Finding): vscode.TreeItem {
    const item = new vscode.TreeItem(`${finding.cve} · ${finding.package}`, vscode.TreeItemCollapsibleState.None);
    item.description = `${finding.severity}${finding.exploited ? " · exploited" : ""}`;
    item.tooltip = hoverMarkdown(finding);
    item.iconPath = new vscode.ThemeIcon(finding.exploited ? "flame" : "warning");
    return item;
  }

  getChildren(): Finding[] { return this.findings; }
}

function hoverMarkdown(finding: Finding): vscode.MarkdownString {
  const lines = [
    `**${finding.cve} · ${finding.package} ${finding.version}**`,
    "",
    `Severity: **${finding.severity}**  `,
    `Known exploitation: **${finding.exploited ? "yes" : "no"}**  `,
    `Fixed version: **${finding.fixed_in || "not published"}**`,
  ];
  if (finding.via?.length) lines.push("", `Dependency path: \`${finding.via.join(" → ")}\``);
  if (finding.summary) lines.push("", finding.summary);
  if (finding.reason) lines.push("", `Why surfaced: ${finding.reason}`);
  if (finding.reachability_evidence?.length) lines.push("", `Evidence: ${finding.reachability_evidence.join("; ")}`);
  const markdown = new vscode.MarkdownString(lines.join("\n"));
  markdown.isTrusted = false;
  return markdown;
}

class WeedoutController implements vscode.Disposable, vscode.HoverProvider {
  private readonly diagnostics = vscode.languages.createDiagnosticCollection("weedout");
  private readonly decoration = vscode.window.createTextEditorDecorationType({
    after: { color: new vscode.ThemeColor("editorCodeLens.foreground"), margin: "0 0 0 1rem" },
  });
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly findings = new Map<string, Finding[]>();
  private readonly occurrences = new Map<string, DependencyOccurrence[]>();
  private readonly disposables: vscode.Disposable[] = [];
  private readonly baselines = new Map<string, Set<string>>();

  constructor(private readonly context: vscode.ExtensionContext, private readonly tree: FindingTree) {
    this.disposables.push(this.diagnostics, this.decoration);
    for (const pattern of [...MANIFEST_PATTERNS, "**/.weedout.yml"]) {
      const watcher = vscode.workspace.createFileSystemWatcher(pattern);
      watcher.onDidCreate((uri) => this.schedule(uri));
      watcher.onDidChange((uri) => this.schedule(uri));
      watcher.onDidDelete((uri) => this.schedule(uri));
      this.disposables.push(watcher);
    }
    this.disposables.push(
      vscode.workspace.onDidSaveTextDocument((document) => {
        if (document.uri.scheme === "file" && (isManifest(document.fileName) || path.basename(document.fileName) === ".weedout.yml")) this.schedule(document.uri);
      }),
      vscode.window.onDidChangeActiveTextEditor(() => this.refreshDecorations()),
      vscode.workspace.onDidChangeWorkspaceFolders(() => void this.scanAll()),
      vscode.languages.registerHoverProvider({ scheme: "file" }, this),
    );
  }

  dispose() {
    for (const timer of this.timers.values()) clearTimeout(timer);
    for (const disposable of this.disposables) disposable.dispose();
  }

  async start() { await this.scanAll(); }

  private schedule(uri: vscode.Uri) {
    const folder = vscode.workspace.getWorkspaceFolder(uri) ?? vscode.workspace.workspaceFolders?.[0];
    if (!folder) return;
    const key = folder.uri.toString();
    const existing = this.timers.get(key);
    if (existing) clearTimeout(existing);
    const delay = vscode.workspace.getConfiguration("weedout").get<number>("scanDebounceMs", 800);
    this.timers.set(key, setTimeout(() => {
      this.timers.delete(key);
      void this.scanFolder(folder, false);
    }, delay));
  }

  async scanAll() {
    for (const folder of vscode.workspace.workspaceFolders ?? []) await this.scanFolder(folder, true);
  }

  private async scanFolder(folder: vscode.WorkspaceFolder, startup: boolean) {
    const binding = this.context.workspaceState.get<ProjectBinding>(`${BINDING}:${folder.uri.toString()}`);
    if (!binding) return;
    const key = await this.context.secrets.get(projectSecret(binding));
    if (!key) return;
    const manifests = await this.findManifests(folder);
    const manifest = manifests[0];
    if (!manifest) {
      this.clearFolder(folder);
      return;
    }

    try {
      const [content, policies] = await Promise.all([
        vscode.workspace.fs.readFile(manifest),
        vscode.workspace.findFiles(new vscode.RelativePattern(folder, ".weedout.yml"), undefined, 1),
      ]);
      const policy = policies[0] ? await vscode.workspace.fs.readFile(policies[0]) : undefined;
      const result = await api().scan(key, path.basename(manifest.fsPath), content, policy);
      this.apply(folder, manifest, content, result.findings, startup);
    } catch (error) {
      console.error("Weedout automatic scan failed", error);
      if (!startup) void vscode.window.showErrorMessage(`Weedout could not update: ${String((error as Error).message ?? error)}`);
    }
  }

  private async findManifests(folder: vscode.WorkspaceFolder): Promise<vscode.Uri[]> {
    const nested = await Promise.all(MANIFEST_PATTERNS.map((pattern) =>
      vscode.workspace.findFiles(new vscode.RelativePattern(folder, pattern), EXCLUDES, 50),
    ));
    return nested.flat().sort((a, b) => manifestRank(a.fsPath) - manifestRank(b.fsPath) || a.fsPath.length - b.fsPath.length);
  }

  private apply(folder: vscode.WorkspaceFolder, manifest: vscode.Uri, content: Uint8Array, findings: Finding[], startup: boolean) {
    this.clearFolder(folder);
    const text = new TextDecoder().decode(content);
    const occurrences = findDependencyOccurrences(text, path.basename(manifest.fsPath));
    const byPackage = new Map(findings.map((finding) => [dependencyKey(finding.package), finding]));
    const matched = occurrences.filter((entry) => byPackage.has(dependencyKey(entry.package)));
    const lines = text.split(/\r?\n/);
    const diagnostics = matched.map((entry) => {
      const finding = byPackage.get(dependencyKey(entry.package))!;
      const range = new vscode.Range(entry.line, entry.start, entry.line, entry.end);
      const diagnostic = new vscode.Diagnostic(range, `${finding.cve} · ${finding.severity}${finding.fixed_in ? ` · fix ${finding.fixed_in}` : ""}`, severity(finding));
      diagnostic.source = "Weedout";
      diagnostic.code = finding.cve;
      return diagnostic;
    });
    this.diagnostics.set(manifest, diagnostics);
    this.findings.set(manifest.toString(), findings);
    this.occurrences.set(manifest.toString(), matched);
    this.tree.update(findings);
    this.refreshDecorations();

    const baselineKey = folder.uri.toString();
    const baselineInitialized = this.baselines.has(baselineKey);
    const previous = this.baselines.get(baselineKey) ?? new Set<string>();
    const next = new Set(findings.map((finding) => `${finding.cve}:${finding.package}:${finding.version}`));
    const added = [...next].filter((id) => !previous.has(id));
    if (!startup && baselineInitialized && added.length > 0) {
      void vscode.window.showWarningMessage(`Weedout found ${added.length} new ${added.length === 1 ? "finding" : "findings"}.`);
    }
    this.baselines.set(baselineKey, next);

    // Keep line lengths available for a document that has not been opened yet.
    void lines;
  }

  private clearFolder(folder: vscode.WorkspaceFolder) {
    for (const [uri] of this.findings) {
      if (vscode.workspace.getWorkspaceFolder(vscode.Uri.parse(uri))?.uri.toString() === folder.uri.toString()) {
        this.diagnostics.delete(vscode.Uri.parse(uri));
        this.findings.delete(uri);
        this.occurrences.delete(uri);
      }
    }
    this.refreshDecorations();
  }

  private refreshDecorations() {
    for (const editor of vscode.window.visibleTextEditors) {
      const uri = editor.document.uri.toString();
      const findings = new Map((this.findings.get(uri) ?? []).map((finding) => [dependencyKey(finding.package), finding]));
      const options: vscode.DecorationOptions[] = (this.occurrences.get(uri) ?? []).flatMap((entry) => {
        const finding = findings.get(dependencyKey(entry.package));
        if (!finding) return [];
        return [{ range: new vscode.Range(entry.line, entry.end, entry.line, entry.end), renderOptions: { after: { contentText: inlineHint(finding) } } }];
      });
      editor.setDecorations(this.decoration, options);
    }
  }

  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
    const uri = document.uri.toString();
    const findings = new Map((this.findings.get(uri) ?? []).map((finding) => [dependencyKey(finding.package), finding]));
    const occurrence = (this.occurrences.get(uri) ?? []).find((entry) => entry.line === position.line && position.character >= entry.start && position.character <= entry.end);
    const finding = occurrence ? findings.get(dependencyKey(occurrence.package)) : undefined;
    return finding ? new vscode.Hover(hoverMarkdown(finding)) : undefined;
  }
}

function severity(finding: Finding): vscode.DiagnosticSeverity {
  return finding.severity === "critical" || finding.exploited
    ? vscode.DiagnosticSeverity.Error
    : vscode.DiagnosticSeverity.Warning;
}

async function authenticate(context: vscode.ExtensionContext): Promise<string | undefined> {
  const started = await api().startAuth(`VS Code on ${os.hostname()}`);
  const choice = await vscode.window.showInformationMessage(
    `Confirm Weedout code ${started.user_code} in your browser.`, "Open browser",
  );
  if (choice === "Open browser") await vscode.env.openExternal(vscode.Uri.parse(started.verification_url));
  const deadline = Date.now() + started.expires_in * 1000;
  return vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `Weedout: waiting for ${started.user_code}`, cancellable: true }, async (_progress, token) => {
    while (!token.isCancellationRequested && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, started.interval * 1000));
      const result = await api().pollAuth(started.device_code);
      if (result.state === "approved" && result.token) {
        await context.secrets.store(MACHINE_TOKEN, result.token);
        void vscode.window.showInformationMessage(`Weedout authenticated as ${result.email}.`);
        return result.token;
      }
      if (["denied", "expired"].includes(result.state)) throw new Error(`Authentication ${result.state}.`);
    }
    return undefined;
  });
}

async function manifestFor(folder: vscode.WorkspaceFolder): Promise<vscode.Uri | undefined> {
  const files = (await Promise.all(MANIFEST_PATTERNS.map((pattern) =>
    vscode.workspace.findFiles(new vscode.RelativePattern(folder, pattern), EXCLUDES, 50),
  ))).flat();
  return files.sort((a, b) => manifestRank(a.fsPath) - manifestRank(b.fsPath) || a.fsPath.length - b.fsPath.length)[0];
}

export async function activate(context: vscode.ExtensionContext) {
  const tree = new FindingTree();
  const controller = new WeedoutController(context, tree);
  context.subscriptions.push(controller, vscode.window.registerTreeDataProvider("weedout.findings", tree));

  context.subscriptions.push(
    vscode.commands.registerCommand("weedout.auth", () => authenticate(context)),
    vscode.commands.registerCommand("weedout.rules", async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) return void vscode.window.showErrorMessage("Open a folder first.");
      const uri = vscode.Uri.joinPath(folder.uri, ".weedout.yml");
      try { await vscode.workspace.fs.stat(uri); } catch { await vscode.workspace.fs.writeFile(uri, new TextEncoder().encode("# Weedout project rules\n")); }
      await vscode.window.showTextDocument(uri);
    }),
    vscode.commands.registerCommand("weedout.createProject", async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) return void vscode.window.showErrorMessage("Open a folder first.");
      const manifest = await manifestFor(folder);
      if (!manifest) return void vscode.window.showErrorMessage("No supported dependency file was found.");
      let machine = await context.secrets.get(MACHINE_TOKEN);
      if (!machine) machine = await authenticate(context);
      if (!machine) return;
      const name = await vscode.window.showInputBox({ prompt: "Weedout project name", value: path.basename(folder.uri.fsPath), validateInput: (value) => value.trim() ? undefined : "Enter a project name." });
      if (!name) return;
      const content = new TextDecoder().decode(await vscode.workspace.fs.readFile(manifest));
      const created = await api().createProject(machine, { name, filename: path.basename(manifest.fsPath), content });
      const binding: ProjectBinding = { id: created.project.id, name: created.project.name, workspace: folder.uri.toString() };
      await context.workspaceState.update(`${BINDING}:${folder.uri.toString()}`, binding);
      await context.secrets.store(projectSecret(binding), created.key);
      void vscode.window.showInformationMessage(`Weedout project “${created.project.name}” is active.`);
      await controller.scanAll();
    }),
    vscode.commands.registerCommand("weedout.deleteProject", async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) return void vscode.window.showErrorMessage("Open a folder first.");
      const binding = context.workspaceState.get<ProjectBinding>(`${BINDING}:${folder.uri.toString()}`);
      if (!binding) return void vscode.window.showErrorMessage("This workspace has no Weedout project.");
      const confirmed = await vscode.window.showWarningMessage(`Delete Weedout project “${binding.name}”?`, { modal: true }, "Delete");
      if (confirmed !== "Delete") return;
      let machine = await context.secrets.get(MACHINE_TOKEN);
      if (!machine) machine = await authenticate(context);
      if (!machine) return;
      await api().deleteProject(machine, binding.id);
      await context.secrets.delete(projectSecret(binding));
      await context.workspaceState.update(`${BINDING}:${folder.uri.toString()}`, undefined);
      tree.update([]);
      void vscode.window.showInformationMessage(`Deleted Weedout project “${binding.name}”.`);
    }),
  );

  await controller.start();
}

export function deactivate() {}
