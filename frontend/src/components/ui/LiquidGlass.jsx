import { motion, useMotionTemplate, useMotionValue, useReducedMotion, useSpring } from "motion/react";

const ELEMENTS = { div: motion.div, header: motion.header, section: motion.section };

export function LiquidGlass({ as = "div", children, className = "", interactive = false, ...props }) {
  const Component = ELEMENTS[as] || motion.div;
  const reduced = useReducedMotion();
  const rawX = useMotionValue(50);
  const rawY = useMotionValue(20);
  const x = useSpring(rawX, { stiffness: 180, damping: 24, mass: 0.35 });
  const y = useSpring(rawY, { stiffness: 180, damping: 24, mass: 0.35 });
  const sheen = useMotionTemplate`radial-gradient(circle at ${x}% ${y}%, rgb(255 255 255 / .24), transparent 32%)`;

  return <Component
    className={`liquid-glass ${interactive ? "liquid-glass--interactive" : ""} ${className}`.trim()}
    onPointerLeave={() => { rawX.set(50); rawY.set(20); }}
    onPointerMove={interactive && !reduced ? (event) => {
      const bounds = event.currentTarget.getBoundingClientRect();
      rawX.set(((event.clientX - bounds.left) / bounds.width) * 100);
      rawY.set(((event.clientY - bounds.top) / bounds.height) * 100);
    } : undefined}
    {...props}
  >
    <motion.span aria-hidden="true" className="liquid-glass__sheen" style={{ backgroundImage: sheen }} />
    <div className="liquid-glass__content">{children}</div>
  </Component>;
}
