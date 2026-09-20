import { useCallback, useEffect, useState } from "react";

export const MOTION_STORAGE_KEY = "weedout-motion";
export const MOTION_CHOICES = ["system", "full", "reduced"];
const REDUCED_QUERY = "(prefers-reduced-motion: reduce)";

function systemPrefersReducedMotion() {
  try {
    return window.matchMedia(REDUCED_QUERY).matches;
  } catch {
    return false;
  }
}

function readMotionChoice() {
  try {
    const stored = window.localStorage.getItem(MOTION_STORAGE_KEY);
    return MOTION_CHOICES.includes(stored) ? stored : "system";
  } catch {
    return "system";
  }
}

export function resolveReducedMotion(choice) {
  if (choice === "full") return false;
  if (choice === "reduced") return true;
  return systemPrefersReducedMotion();
}

export function applyMotionPreference(choice) {
  const next = MOTION_CHOICES.includes(choice) ? choice : "system";
  document.documentElement.dataset.motion = next;
  try {
    window.localStorage.setItem(MOTION_STORAGE_KEY, next);
  } catch {
    // The preference still applies for this page when storage is unavailable.
  }
  window.dispatchEvent(new CustomEvent("weedout-motion-change", { detail: next }));
}

export function useMotionPreference() {
  const [choice, setChoiceState] = useState(readMotionChoice);
  const [systemReduced, setSystemReduced] = useState(systemPrefersReducedMotion);

  const setChoice = useCallback((next) => {
    applyMotionPreference(next);
    setChoiceState(next);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.motion = choice;
    const onPreference = (event) => setChoiceState(MOTION_CHOICES.includes(event.detail) ? event.detail : readMotionChoice());
    const onStorage = (event) => {
      if (event.key !== MOTION_STORAGE_KEY) return;
      const next = MOTION_CHOICES.includes(event.newValue) ? event.newValue : "system";
      document.documentElement.dataset.motion = next;
      setChoiceState(next);
    };
    let media;
    try {
      media = window.matchMedia(REDUCED_QUERY);
      const onSystem = (event) => setSystemReduced(event.matches);
      media.addEventListener("change", onSystem);
      window.addEventListener("weedout-motion-change", onPreference);
      window.addEventListener("storage", onStorage);
      return () => {
        media.removeEventListener("change", onSystem);
        window.removeEventListener("weedout-motion-change", onPreference);
        window.removeEventListener("storage", onStorage);
      };
    } catch {
      window.addEventListener("weedout-motion-change", onPreference);
      window.addEventListener("storage", onStorage);
      return () => {
        window.removeEventListener("weedout-motion-change", onPreference);
        window.removeEventListener("storage", onStorage);
      };
    }
  }, [choice]);

  const reduced = choice === "reduced" || (choice === "system" && systemReduced);
  return { choice, reduced, setChoice };
}
