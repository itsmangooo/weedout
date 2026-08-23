import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Light and dark must describe the same set of tokens.
 *
 * The failure mode is adding a token to one palette and not the other: the
 * missing one then falls through to whatever `:root` set, so a dark page ends
 * up with one cream-coloured thing on it. Nobody notices until they are
 * looking at the wrong theme, which is the theme nobody has open.
 *
 * Parsed rather than rendered, because jsdom will not compute custom
 * properties across two selector blocks for us.
 */

// `import.meta.url` is a Vite dev-server URL under vitest, not a file: one.
const CSS = readFileSync(join(dirname(__filename ?? ""), "themes.css"), "utf8");

function block(startPattern) {
  const start = CSS.indexOf(startPattern);
  expect(start, `block not found: ${startPattern}`).toBeGreaterThan(-1);

  let depth = 0;
  for (let i = start; i < CSS.length; i += 1) {
    if (CSS[i] === "{") depth += 1;
    if (CSS[i] === "}") {
      depth -= 1;
      if (depth === 0) return CSS.slice(start, i);
    }
  }
  throw new Error(`unterminated block: ${startPattern}`);
}

function assignments(text) {
  return [...text.matchAll(/(--wo-[\w-]+)\s*:\s*([^;]+);/g)].map(([, name, value]) => [
    name,
    value.trim(),
  ]);
}

describe("the theme token mappings", () => {
  const dark = assignments(block(':root[data-theme="dark"]'));
  const light = assignments(block("/* --- Mapping: light"));

  it("found something to compare", () => {
    // Guards every assertion below from passing on an empty parse.
    expect(dark.length).toBeGreaterThan(15);
    expect(light.length).toBeGreaterThan(15);
  });

  it("covers exactly the same token names in light and dark", () => {
    const names = (pairs) => pairs.map(([name]) => name).sort();
    expect(names(light)).toEqual(names(dark));
  });

  it("leaves no `prefers-color-scheme` rule to overrule a stated choice", () => {
    /* The boot script resolves "match system" to a concrete value. A media
       rule here would additionally flip the palette for somebody who asked
       for light on a machine set to dark. */
    expect(CSS).not.toContain("prefers-color-scheme:");
  });

  it("maps every token to a palette value rather than a literal", () => {
    /* A literal here is a colour that cannot follow the theme — the thing
       this file exists to prevent. */
    for (const [name, value] of [...light, ...dark]) {
      expect(value, `${name} should reference a palette variable`).toMatch(
        /^var\(--wo-(light|dark)-[\w-]+\)$/,
      );
    }
  });

  it("defines both palettes for every mapped token", () => {
    for (const [, value] of light) {
      expect(CSS).toContain(`${value.slice("var(".length, -1)}:`);
    }
    for (const [, value] of dark) {
      expect(CSS).toContain(`${value.slice("var(".length, -1)}:`);
    }
  });
});
