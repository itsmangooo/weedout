import { useEffect, useRef } from "react";
export function PageTransition({ children }) {
  const region = useRef(null);
  useEffect(() => {
    if (window.location.hash) return;
    const frame = requestAnimationFrame(() => {
      window.scrollTo({ top: 0, left: 0, behavior: "instant" });
      region.current?.closest("main")?.focus({ preventScroll: true });
    });
    return () => cancelAnimationFrame(frame);
  }, []);
  return <div ref={region} className="route-transition">{children}</div>;
}
