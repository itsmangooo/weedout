import { useEffect } from "react";

// Load animation infrastructure only on the public landing. Every observer,
// ticker, listener and inline animation is owned by this effect and reverted.
export function useLandingMotion(ref) {
  useEffect(() => {
    if (!window.matchMedia || !ref.current) return;
    let cancelled = false;
    let dispose = () => {};
    Promise.all([import("gsap"), import("gsap/ScrollTrigger"), import("lenis")]).then(([{ gsap }, { ScrollTrigger }, { default: Lenis }]) => {
      if (cancelled) return;
      gsap.registerPlugin(ScrollTrigger);
      const media = gsap.matchMedia();
      dispose = () => media.revert();
      media.add("(prefers-reduced-motion: no-preference)", () => {
        const root = ref.current;
        root.querySelectorAll("[data-reveal]").forEach((node) => {
          gsap.fromTo(node, { y: 28, opacity: 0.25, clipPath: "inset(0 0 12% 0)" }, {
            y: 0, opacity: 1, clipPath: "inset(0 0 0% 0)", duration: 0.75, ease: "power3.out",
            scrollTrigger: { trigger: node, start: "top 92%", once: true },
          });
        });
        gsap.fromTo(root.querySelectorAll("[data-text-line]"), { yPercent: 105 }, { yPercent: 0, duration: 0.95, stagger: 0.12, ease: "power3.out" });
      }, ref);
      media.add("(min-width: 960px) and (pointer: fine) and (prefers-reduced-motion: no-preference)", () => {
        const lenis = new Lenis({ lerp: 0.12, anchors: { offset: -90 }, prevent: (node) => node.hasAttribute("data-native-scroll") });
        const tick = (time) => lenis.raf(time * 1000);
        lenis.on("scroll", ScrollTrigger.update);
        gsap.ticker.add(tick);
        const scene = ref.current.querySelector("[data-analysis-stage]");
        const story = ref.current.querySelector("[data-analysis-story]");
        const progress = { value: 0 };
        const update = () => story.dispatchEvent(new CustomEvent("analysis-progress", { detail: progress.value }));
        gsap.to(progress, { value: 1, ease: "none", onUpdate: update,
          scrollTrigger: { trigger: story, start: "top 90px", end: "+=950", pin: scene, scrub: 0.7, invalidateOnRefresh: true },
        });
        gsap.to(ref.current.querySelector(".landing-manifest"), { y: -35, ease: "none", scrollTrigger: { trigger: ".landing-method", start: "top bottom", end: "bottom top", scrub: true } });
        return () => { gsap.ticker.remove(tick); lenis.destroy(); };
      }, ref);
      const refresh = () => { if (!cancelled) ScrollTrigger.refresh(); };
      document.fonts?.ready.then(refresh);
      dispose = () => media.revert();
    }).catch(() => { dispose(); /* The page remains completely usable without enhancement. */ });
    return () => { cancelled = true; dispose(); };
  }, [ref]);
}
