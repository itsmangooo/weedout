import { useCallback, useEffect, useState } from "react";

/**
 * The reader's theme choice.
 *
 * Three states, not two. "System" is a real choice, so it has to be selectable
 * rather than only being what you get before you touch anything — otherwise
 * somebody who tries dark can never get back to following their machine.
 *
 * It is not the *default*, though: light is. The cream ground is the design,
 * and a reader on a dark machine who has said nothing should still see the
 * product as drawn. Saying "system" is how they hand that decision over.
 *
 * The storage key and the resolved attribute are the same ones
 * `theme-boot.js` reads and writes before the first paint. That contract is
 * the whole point of this module; `layoutTheme.test.jsx` pins it.
 */

export const THEME_STORAGE_KEY = "weedout-theme";
export const THEMES = ["light", "system", "dark"];

const DARK_QUERY = "(prefers-color-scheme: dark)";

function systemPrefersDark() {
  try {
    return window.matchMedia(DARK_QUERY).matches;
  } catch {
    return false;
  }
}

/** The concrete palette a choice resolves to right now. */
export function resolveTheme(choice) {
  if (choice === "dark") return "dark";
  if (choice === "system") return systemPrefersDark() ? "dark" : "light";
  return "light";
}

function readChoice() {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    return THEMES.includes(stored) ? stored : "light";
  } catch {
    // Storage unavailable. The boot script made the same call and landed on
    // the same answer, so the control agrees with the page.
    return "light";
  }
}

export function applyTheme(choice) {
  document.documentElement.setAttribute("data-theme", resolveTheme(choice));

  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, choice);
  } catch {
    // It still applies for this page; it just will not be remembered.
  }
}

export function useTheme() {
  const [theme, setThemeState] = useState(readChoice);

  const setTheme = useCallback((choice) => {
    applyTheme(choice);
    setThemeState(choice);
  }, []);

  // Two things can change the answer without this tab doing anything: the
  // reader switching theme in another tab, and — while they are on "system" —
  // their machine flipping at sunset.
  useEffect(() => {
    function onStorage(event) {
      if (event.key !== THEME_STORAGE_KEY) return;
      const next = THEMES.includes(event.newValue) ? event.newValue : "light";
      document.documentElement.setAttribute("data-theme", resolveTheme(next));
      setThemeState(next);
    }

    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  useEffect(() => {
    if (theme !== "system") return undefined;

    let media;
    try {
      media = window.matchMedia(DARK_QUERY);
    } catch {
      return undefined;
    }

    function onChange() {
      document.documentElement.setAttribute("data-theme", resolveTheme("system"));
    }

    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [theme]);

  return { theme, setTheme };
}
