import { motion, useMotionValue, useSpring, useTransform } from "motion/react";
import { useEffect } from "react";

export function AnimatedNumber({ value }) {
  const source = useMotionValue(value);
  const spring = useSpring(source, { damping: 30, stiffness: 210 });
  const rounded = useTransform(spring, (latest) => Math.round(latest));

  useEffect(() => {
    source.set(value);
  }, [source, value]);

  return <motion.span>{rounded}</motion.span>;
}
