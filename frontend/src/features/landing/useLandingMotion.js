import { useEffect } from "react";

// Load animation infrastructure only on the public landing. Every observer,
// ticker, listener and inline animation is owned by this effect and reverted.
export function useLandingMotion(ref, reducedMotion = false) {
  useEffect(() => {
    if (!window.matchMedia || !ref.current || reducedMotion) return;
    let cancelled = false;
    let dispose = () => {};
    Promise.all([import("gsap"), import("gsap/ScrollTrigger"), import("lenis")]).then(([{ gsap }, { ScrollTrigger }, { default: Lenis }]) => {
      if (cancelled) return;
      gsap.registerPlugin(ScrollTrigger);
      const media = gsap.matchMedia();
      let removeHeroListeners = () => {};
      const context = gsap.context(() => {
        const root = ref.current;
        const intro = root.querySelector(".landing-hero");
        const heroLayer = root.querySelector("[data-hero-depth]");
        const heroTimeline = gsap.timeline({ defaults: { ease: "power3.out" } });
        heroTimeline
          .fromTo(root.querySelector(".landing-hero__top"), { y: -12, opacity: 0 }, { y: 0, opacity: 1, duration: 0.55 })
          .fromTo(root.querySelectorAll("[data-text-line]"), { yPercent: 112 }, { yPercent: 0, duration: 1.05, stagger: 0.13 }, "-=.25")
          .fromTo(root.querySelectorAll("[data-hero-copy]"), { y: 20, opacity: 0 }, { y: 0, opacity: 1, duration: 0.7, stagger: 0.08 }, "-=.55")
          .fromTo(root.querySelectorAll("[data-hero-signal]"), { scaleX: 0, opacity: 0 }, { scaleX: 1, opacity: 1, duration: 0.65, stagger: 0.1, transformOrigin: "left" }, "-=.45");

        root.querySelectorAll("[data-hero-point]").forEach((point, index) => {
          gsap.to(point, { y: index % 2 ? 12 : -12, x: index % 3 ? 5 : -5, duration: 2.4 + index * 0.13, repeat: -1, yoyo: true, ease: "sine.inOut" });
        });

        let moveHero;
        let leaveHero;
        if (window.matchMedia("(pointer: fine)").matches && intro && heroLayer) {
          moveHero = (event) => {
            const bounds = intro.getBoundingClientRect();
            const x = (event.clientX - bounds.left) / bounds.width - 0.5;
            const y = (event.clientY - bounds.top) / bounds.height - 0.5;
            gsap.to(heroLayer, { x: x * 24, y: y * 16, rotateX: y * -2, rotateY: x * 3, duration: 0.7, ease: "power2.out", overwrite: "auto" });
          };
          leaveHero = () => gsap.to(heroLayer, { x: 0, y: 0, rotateX: 0, rotateY: 0, duration: 0.9, ease: "power3.out" });
          intro.addEventListener("pointermove", moveHero);
          intro.addEventListener("pointerleave", leaveHero);
          removeHeroListeners = () => {
            intro.removeEventListener("pointermove", moveHero);
            intro.removeEventListener("pointerleave", leaveHero);
          };
        }

        root.querySelectorAll("[data-reveal]").forEach((node) => {
          gsap.fromTo(node, { y: 38, opacity: 0, clipPath: "inset(0 0 18% 0)" }, {
            y: 0, opacity: 1, clipPath: "inset(0 0 0% 0)", duration: 0.85, ease: "power3.out",
            scrollTrigger: { trigger: node, start: "top 88%", once: true },
          });
        });

        root.querySelectorAll("[data-section]").forEach((section, index) => {
          if (index === 0) return;
          gsap.fromTo(section, { opacity: 0.62, "--section-reveal": 0 }, {
            opacity: 1, "--section-reveal": 1, duration: 0.9, ease: "power2.out",
            scrollTrigger: { trigger: section, start: "top 92%", once: true },
          });
        });

        gsap.to(root.querySelector(".landing-hero__visual img"), { yPercent: 8, scale: 1.1, ease: "none", scrollTrigger: { trigger: ".landing-hero__visual", start: "top bottom", end: "bottom top", scrub: 0.5 } });
        gsap.to(root.querySelector(".hero-finding"), { y: -26, ease: "none", scrollTrigger: { trigger: ".landing-hero__visual", start: "top bottom", end: "bottom top", scrub: 0.4 } });
        gsap.to(root.querySelector(".landing-conclusion h2"), { backgroundPositionX: "0%", ease: "none", scrollTrigger: { trigger: ".landing-conclusion", start: "top 75%", end: "bottom bottom", scrub: true } });
      }, ref);
      media.add("(min-width: 960px) and (pointer: fine)", () => {
        const lenis = new Lenis({ duration: 1.05, smoothWheel: true, anchors: { offset: -90 }, prevent: (node) => node.hasAttribute("data-native-scroll") });
        const tick = (time) => lenis.raf(time * 1000);
        lenis.on("scroll", ScrollTrigger.update);
        gsap.ticker.lagSmoothing(0);
        gsap.ticker.add(tick);
        const scene = ref.current.querySelector("[data-analysis-stage]");
        const story = ref.current.querySelector("[data-analysis-story]");
        const progress = { value: 0 };
        const update = () => story.dispatchEvent(new CustomEvent("analysis-progress", { detail: progress.value }));
        gsap.to(progress, { value: 1, ease: "none", onUpdate: update,
          scrollTrigger: { trigger: story, start: "top 90px", end: "+=950", pin: scene, scrub: 0.7, invalidateOnRefresh: true },
        });
        gsap.to(ref.current.querySelector(".landing-manifest"), { y: -55, rotate: 1.5, ease: "none", scrollTrigger: { trigger: ".landing-method", start: "top bottom", end: "bottom top", scrub: true } });
        return () => { gsap.ticker.remove(tick); lenis.destroy(); };
      }, ref);
      const refresh = () => { if (!cancelled) ScrollTrigger.refresh(); };
      document.fonts?.ready.then(refresh);
      dispose = () => { removeHeroListeners(); context.revert(); media.revert(); };
    }).catch(() => { dispose(); /* The page remains completely usable without enhancement. */ });
    return () => { cancelled = true; dispose(); };
  }, [ref, reducedMotion]);
}
