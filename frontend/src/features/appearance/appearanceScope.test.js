import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

const styles = join(dirname(__filename ?? ""), "../../styles");
const read = (name) => readFileSync(join(styles, name), "utf8");

describe("appearance scope", () => {
  it("limits selectable palettes, type scales and glass fallback to panel shells", () => {
    const themes = read("themes.css");
    const tokens = read("tokens.css");
    const glass = read("glass.css");

    expect(themes).toContain(':root[data-panel-scheme="clay"] :is(.workspace-shell,.operations-shell)');
    expect(themes).not.toContain(":root[data-scheme=");
    expect(tokens).toContain(':root[data-panel-font="technical"] :is(.workspace-shell,.operations-shell)');
    expect(tokens).toContain(':root[data-panel-scale="large"] :is(.workspace-shell,.operations-shell)');
    expect(glass).toContain(':root[data-panel-glass="solid"] :is(.workspace-shell,.operations-shell)');
  });

  it("gives public and authentication routes one fixed non-green palette", () => {
    const publicStyles = read("public.css");
    expect(publicStyles).toContain(".public-shell {");
    expect(publicStyles).toContain("--wo-accent:#a55b3b");
    expect(publicStyles).not.toContain("data-panel-scheme");
  });
});
