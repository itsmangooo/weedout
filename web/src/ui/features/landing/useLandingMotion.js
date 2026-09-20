import { useEffect } from "react";

// Motion is progressive enhancement. The demo and every action remain usable
// when animation modules are unavailable or the reader prefers less motion.
export function useLandingMotion(ref, reducedMotion = false) {
  useEffect(() => {
    if (!window.matchMedia || !ref.current || reducedMotion) return;
    let cancelled = false;
    let dispose = () => {};

    Promise.all([import("gsap"), import("gsap/ScrollTrigger"), import("lenis")])
      .then(([{ gsap }, { ScrollTrigger }, { default: Lenis }]) => {
        if (cancelled || !ref.current) return;
        gsap.registerPlugin(ScrollTrigger);
        const root = ref.current;
        const context = gsap.context(() => {
          const timeline = gsap.timeline({ defaults: { ease: "power3.out" } });
          const top = root.querySelector(".landing-hero__top");
          if (top) timeline.fromTo(top, { y: -10, opacity: 0 }, { y: 0, opacity: 1, duration: 0.5 });
          timeline
            .fromTo(root.querySelectorAll("[data-text-line]"), { yPercent: 112 }, { yPercent: 0, duration: 0.85, stagger: 0.1 }, "-=.2")
            .fromTo(root.querySelectorAll("[data-hero-copy]"), { y: 18, opacity: 0 }, { y: 0, opacity: 1, duration: 0.65, stagger: 0.08 }, "-=.45");

          root.querySelectorAll("[data-reveal]").forEach((node) => {
            gsap.fromTo(node, { y: 28, opacity: 0 }, {
              y: 0,
              opacity: 1,
              duration: 0.75,
              ease: "power3.out",
              scrollTrigger: { trigger: node, start: "top 90%", once: true },
            });
          });

          const hero = root.querySelector(".landing-hero");
          const depth = root.querySelector("[data-hero-depth]");
          if (hero && depth && window.matchMedia("(pointer: fine)").matches) {
            const move = (event) => {
              const bounds = hero.getBoundingClientRect();
              const x = (event.clientX - bounds.left) / bounds.width - 0.5;
              const y = (event.clientY - bounds.top) / bounds.height - 0.5;
              gsap.to(depth, { x: x * 10, y: y * 8, rotateX: y * -1.5, rotateY: x * 2, duration: 0.6, overwrite: "auto" });
            };
            const leave = () => gsap.to(depth, { x: 0, y: 0, rotateX: 0, rotateY: 0, duration: 0.7 });
            hero.addEventListener("pointermove", move);
            hero.addEventListener("pointerleave", leave);
            context.add(() => {
              hero.removeEventListener("pointermove", move);
              hero.removeEventListener("pointerleave", leave);
            });
          }
        }, ref);

        let lenis;
        let tick;
        if (window.matchMedia("(min-width: 960px) and (pointer: fine)").matches) {
          lenis = new Lenis({ duration: 1, smoothWheel: true, anchors: { offset: -80 } });
          tick = (time) => lenis.raf(time * 1000);
          lenis.on("scroll", ScrollTrigger.update);
          gsap.ticker.add(tick);
        }

        document.fonts?.ready.then(() => !cancelled && ScrollTrigger.refresh());
        dispose = () => {
          if (tick) gsap.ticker.remove(tick);
          lenis?.destroy();
          context.revert();
        };
      })
      .catch(() => dispose());

    return () => {
      cancelled = true;
      dispose();
    };
  }, [ref, reducedMotion]);
}
