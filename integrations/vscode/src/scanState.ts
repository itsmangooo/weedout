/**
 * Tracks the newest automatic scan for each workspace. Filesystem events can
 * arrive while an earlier network request is still running; only the newest
 * request may update diagnostics or findings.
 */
export class ScanState {
  private readonly versions = new Map<string, number>();

  begin(workspace: string): number {
    const version = (this.versions.get(workspace) ?? 0) + 1;
    this.versions.set(workspace, version);
    return version;
  }

  isCurrent(workspace: string, version: number): boolean {
    return this.versions.get(workspace) === version;
  }

  invalidate(workspace: string): void {
    this.begin(workspace);
  }
}
