import { ArrowRight } from "lucide-react";
import { motion, useMotionValue, useReducedMotion, useSpring } from "motion/react";
import { Link } from "react-router";

export function MagneticLink({ children, className = "", to }) {
  const reduceMotion = useReducedMotion();
  const offsetX = useMotionValue(0);
  const offsetY = useMotionValue(0);
  const x = useSpring(offsetX, { damping: 18, stiffness: 260 });
  const y = useSpring(offsetY, { damping: 18, stiffness: 260 });

  function handlePointerMove(event) {
    if (reduceMotion || event.pointerType === "touch") return;
    const bounds = event.currentTarget.getBoundingClientRect();
    offsetX.set((event.clientX - bounds.left - bounds.width / 2) * 0.12);
    offsetY.set((event.clientY - bounds.top - bounds.height / 2) * 0.12);
  }

  function reset() {
    offsetX.set(0);
    offsetY.set(0);
  }

  return (
    <motion.div
      className={`magnetic-link ${className}`.trim()}
      onPointerLeave={reset}
      onPointerMove={handlePointerMove}
      style={{ x, y }}
      whileHover="hover"
    >
      <Link to={to}>
        <span>{children}</span>
        <motion.span
          aria-hidden="true"
          className="magnetic-link__arrow"
          variants={{ hover: { x: 3 } }}
        >
          <ArrowRight size={16} />
        </motion.span>
      </Link>
    </motion.div>
  );
}
