import { Monitor, Moon, Sun } from "lucide-react";

import { useTheme } from "./useTheme";

const OPTIONS = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "system", label: "Match system", Icon: Monitor },
  { value: "dark", label: "Dark", Icon: Moon },
];

/**
 * Three segments rather than a two-state switch.
 *
 * A toggle can only say light-or-dark, which forces a reader who tried one to
 * keep choosing forever — there is no way back to "whatever my machine is
 * doing". The middle option is the default, so it is also the one most people
 * should be able to return to.
 *
 * `radiogroup` rather than buttons: these are three settings of one thing, and
 * arrow keys should move between them the way they do in every other radio
 * group.
 */
export function ThemeControl({ className = "" }) {
  const { theme, setTheme } = useTheme();

  return (
    <div
      aria-label="Colour theme"
      className={`theme-control ${className}`.trim()}
      role="radiogroup"
    >
      {OPTIONS.map(({ value, label, Icon }) => (
        <button
          aria-checked={theme === value}
          className="theme-control__option"
          key={value}
          onClick={() => setTheme(value)}
          role="radio"
          title={label}
          type="button"
        >
          <Icon aria-hidden="true" size={15} strokeWidth={1.9} />
          <span className="visually-hidden">{label}</span>
        </button>
      ))}
    </div>
  );
}
