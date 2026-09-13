import { useRef } from "react";
import { Link } from "react-router";

export function MagneticLink({ children, to, className = "" }) {
  const ref = useRef(null);
  function reset() { ref.current?.style.removeProperty("transform"); }
  function move(event) {
    if (!window.matchMedia?.("(pointer: fine) and (prefers-reduced-motion: no-preference)").matches) return;
    const rect = event.currentTarget.getBoundingClientRect();
    ref.current.style.transform = `translate(${(event.clientX - rect.left - rect.width / 2) * 0.055}px, ${(event.clientY - rect.top - rect.height / 2) * 0.12}px)`;
  }
  return <Link ref={ref} to={to} className={`button button--primary magnetic ${className}`} onPointerMove={move} onPointerLeave={reset} onBlur={reset}>{children}</Link>;
}
