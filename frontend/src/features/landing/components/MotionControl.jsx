import { Monitor, Pause, Play } from "lucide-react";
import { useMotionPreference } from "../useMotionPreference";

const OPTIONS = [
  { value: "system", label: "Use system motion setting", Icon: Monitor },
  { value: "full", label: "Play full motion", Icon: Play },
  { value: "reduced", label: "Reduce motion", Icon: Pause },
];

export function MotionControl() {
  const { choice, setChoice } = useMotionPreference();
  return <div className="motion-setting">
    <span>Motion</span>
    <div
      aria-label="Motion preference"
      className="motion-control"
      role="radiogroup"
      onKeyDown={(event) => {
        const current = OPTIONS.findIndex((option) => option.value === choice);
        const next = event.key === "ArrowRight" || event.key === "ArrowDown" ? (current + 1) % OPTIONS.length : event.key === "ArrowLeft" || event.key === "ArrowUp" ? (current + OPTIONS.length - 1) % OPTIONS.length : event.key === "Home" ? 0 : event.key === "End" ? OPTIONS.length - 1 : null;
        if (next === null) return;
        event.preventDefault();
        setChoice(OPTIONS[next].value);
        event.currentTarget.querySelectorAll('[role="radio"]')[next]?.focus();
      }}
    >
      {OPTIONS.map(({ value, label, Icon }) => <button
        aria-checked={choice === value}
        key={value}
        onClick={() => setChoice(value)}
        role="radio"
        tabIndex={choice === value ? 0 : -1}
        title={label}
        type="button"
      ><Icon aria-hidden="true" size={13} /><span className="visually-hidden">{label}</span></button>)}
    </div>
  </div>;
}
