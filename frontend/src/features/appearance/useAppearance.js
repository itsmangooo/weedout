import { useCallback, useEffect, useState } from "react";

export const APPEARANCE_STORAGE_KEY = "weedout-appearance";
export const DEFAULT_APPEARANCE = Object.freeze({ scheme: "forest", font: "poppins", scale: "default", glass: true });
export const SCHEMES = ["forest", "mineral", "clay", "mono"];
export const FONTS = ["poppins", "system", "editorial", "technical"];
export const SCALES = ["compact", "default", "large"];

function validate(value = {}) {
  return {
    scheme: SCHEMES.includes(value.scheme) ? value.scheme : DEFAULT_APPEARANCE.scheme,
    font: FONTS.includes(value.font) ? value.font : DEFAULT_APPEARANCE.font,
    scale: SCALES.includes(value.scale) ? value.scale : DEFAULT_APPEARANCE.scale,
    glass: typeof value.glass === "boolean" ? value.glass : DEFAULT_APPEARANCE.glass,
  };
}

export function readAppearance() {
  try {
    return validate(JSON.parse(window.localStorage.getItem(APPEARANCE_STORAGE_KEY) || "{}"));
  } catch {
    return { ...DEFAULT_APPEARANCE };
  }
}

export function applyAppearance(value, { persist = true } = {}) {
  const next = validate(value);
  const root = document.documentElement;
  root.dataset.scheme = next.scheme;
  root.dataset.font = next.font;
  root.dataset.scale = next.scale;
  root.dataset.glass = next.glass ? "liquid" : "solid";
  if (persist) {
    try { window.localStorage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify(next)); } catch { /* Applied for this page. */ }
  }
  window.dispatchEvent(new CustomEvent("weedout-appearance-change", { detail: next }));
  return next;
}

export function initializeAppearance() {
  return applyAppearance(readAppearance(), { persist: false });
}

export function useAppearance() {
  const [appearance, setAppearanceState] = useState(readAppearance);
  const setAppearance = useCallback((patch) => {
    setAppearanceState((current) => applyAppearance({ ...current, ...patch }));
  }, []);

  useEffect(() => {
    const sync = (event) => setAppearanceState(validate(event.detail));
    const storage = (event) => {
      if (event.key !== APPEARANCE_STORAGE_KEY) return;
      const next = readAppearance();
      applyAppearance(next, { persist: false });
      setAppearanceState(next);
    };
    window.addEventListener("weedout-appearance-change", sync);
    window.addEventListener("storage", storage);
    return () => {
      window.removeEventListener("weedout-appearance-change", sync);
      window.removeEventListener("storage", storage);
    };
  }, []);

  return { appearance, setAppearance };
}
