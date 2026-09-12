import { useEffect, useRef } from "react";

// Visible by default: animation is never a prerequisite for reading or focus.
export function Reveal({ children, className = "" }) {
  const ref = useRef(null);
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("has-entered");
        observer.disconnect();
      },
      { threshold: 0.08 },
    );
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  return (
    <div ref={ref} className={`landing-reveal ${className}`}>
      {children}
    </div>
  );
}
