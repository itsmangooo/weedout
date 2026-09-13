import { useEffect, useRef } from "react";

const POINTS = Array.from({ length: 47 }, (_, index) => ({
  x: Math.sin(index * 2.399) * (1.1 + (index % 6) * 0.3),
  y: Math.cos(index * 1.719) * (0.7 + (index % 5) * 0.27),
  z: Math.sin(index * 0.91) * 1.2,
}));

const TARGETS = POINTS.map((_, index) => ({
  x: (index % 3 - 1) * 2.2,
  y: index < 3 ? 0.75 : 0.25 - Math.floor(index / 3) * 0.13,
  z: index < 3 ? 0.5 : Math.sin(index) * 0.24,
}));

// One story-specific WebGL scene. No assets or network requests beyond the
// local Three.js chunk. SVG is the baseline for reduced motion/context loss.
export function DependencyField({ storyRef, progress, reducedMotion = false }) {
  const host = useRef(null);
  const progressRef = useRef(progress);
  useEffect(() => {
    progressRef.current = progress;
  }, [progress]);
  useEffect(() => {
    const node = host.current;
    const story = storyRef.current;
    if (!window.matchMedia || !window.WebGL2RenderingContext) return;
    let cancelled = false;
    let dispose = () => {};
    let observer;
    async function start() {
      if (reducedMotion || cancelled) return;
      const THREE = await import("three");
      if (cancelled || reducedMotion) return;
      let renderer;
      try { renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "low-power" }); } catch { return; }
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
      renderer.domElement.setAttribute("aria-hidden", "true");
      const scene = new THREE.Scene();
      const group = new THREE.Group();
      scene.add(group);
      const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 50);
      camera.position.z = 8.5;
      const geometry = new THREE.IcosahedronGeometry(0.095, 1);
      const material = new THREE.MeshBasicMaterial();
      const nodes = new THREE.InstancedMesh(geometry, material, POINTS.length);
      const linesGeometry = new THREE.BufferGeometry();
      const vertices = new Float32Array(POINTS.length * 6);
      linesGeometry.setAttribute("position", new THREE.BufferAttribute(vertices, 3));
      const linesMaterial = new THREE.LineBasicMaterial({ transparent: true, opacity: 0.25 });
      group.add(nodes, new THREE.LineSegments(linesGeometry, linesMaterial));
      const object = new THREE.Object3D();
      const color = new THREE.Color();
      let lost = false;
      let frame = 0;
      let mix = progressRef.current;
      let pointerX = 0;
      let pointerY = 0;
      let renderedX = 0;
      let renderedY = 0;
      let sceneVisible = true;
      let dark = document.documentElement.dataset.theme === "dark";
      function draw(time = 0) {
        if (lost || cancelled) return;
        mix += (progressRef.current - mix) * 0.075;
        renderedX += (pointerX - renderedX) * 0.055;
        renderedY += (pointerY - renderedY) * 0.055;
        const phase = time * 0.00045;
        group.rotation.y = renderedX + Math.sin(phase) * 0.055;
        group.rotation.x = renderedY + Math.cos(phase * 0.8) * 0.025;
        POINTS.forEach((point, index) => {
          const target = TARGETS[index];
          const pulse = Math.sin(phase * 4 + index * 0.62) * 0.035 * (1 - mix);
          object.position.set(point.x + (target.x - point.x) * mix, point.y + (target.y - point.y) * mix + pulse, point.z + (target.z - point.z) * mix);
          object.scale.setScalar((index < 3 ? 1 + mix * 1.6 : 1 - mix * 0.7) * (1 + Math.sin(phase * 5 + index) * 0.08));
          object.updateMatrix(); nodes.setMatrixAt(index, object.matrix);
          color.set(index < 3 ? (index === 1 ? (dark ? "#e9a184" : "#a55734") : (dark ? "#c3d9af" : "#31573a")) : (dark ? "#778f6b" : "#7b8e70"));
          nodes.setColorAt(index, color);
          vertices.set([object.position.x, object.position.y, object.position.z, target.x * mix, 0.75 * mix, 0], index * 6);
        });
        nodes.instanceMatrix.needsUpdate = true;
        nodes.instanceColor.needsUpdate = true;
        linesGeometry.attributes.position.needsUpdate = true;
        linesMaterial.color.set(dark ? "#b7cfaa" : "#496e39");
        linesMaterial.opacity = 0.16 + mix * 0.34 + Math.sin(phase * 3) * 0.025;
        renderer.render(scene, camera);
      }
      function animate(time) {
        if (sceneVisible && !document.hidden) draw(time);
        frame = window.requestAnimationFrame(animate);
      }
      function resize() {
        if (!node.clientWidth || !node.clientHeight) return;
        renderer.setSize(node.clientWidth, node.clientHeight);
        camera.aspect = node.clientWidth / node.clientHeight;
        camera.updateProjectionMatrix();
      }
      function onProgress(event) { progressRef.current = event.detail; }
      function pointer(event) {
        if (!window.matchMedia("(pointer: fine)").matches) return;
        const rect = node.getBoundingClientRect();
        pointerX = (event.clientX - rect.left - rect.width / 2) / rect.width * 0.34;
        pointerY = (event.clientY - rect.top - rect.height / 2) / rect.height * 0.2;
      }
      function reset() { pointerX = 0; pointerY = 0; }
      function onLost(event) { event.preventDefault(); lost = true; window.cancelAnimationFrame(frame); node.dataset.ready = "false"; }
      node.append(renderer.domElement);
      node.dataset.ready = "true";
      renderer.domElement.addEventListener("webglcontextlost", onLost);
      node.addEventListener("pointermove", pointer);
      node.addEventListener("pointerleave", reset);
      story.addEventListener("analysis-progress", onProgress);
      const resizeObserver = new ResizeObserver(resize); resizeObserver.observe(node);
      const renderObserver = new IntersectionObserver(([entry]) => { sceneVisible = entry.isIntersecting; }, { rootMargin: "100px" }); renderObserver.observe(node);
      const themeObserver = new MutationObserver(() => { dark = document.documentElement.dataset.theme === "dark"; }); themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
      resize();
      frame = window.requestAnimationFrame(animate);
      dispose = () => {
        window.cancelAnimationFrame(frame);
        resizeObserver.disconnect(); renderObserver.disconnect(); themeObserver.disconnect();
        node.removeEventListener("pointermove", pointer); node.removeEventListener("pointerleave", reset);
        story.removeEventListener("analysis-progress", onProgress);
        renderer.domElement.removeEventListener("webglcontextlost", onLost);
        geometry.dispose(); material.dispose(); linesGeometry.dispose(); linesMaterial.dispose();
        renderer.dispose(); renderer.forceContextLoss(); renderer.domElement.remove(); node.dataset.ready = "false";
      };
    }
    const safelyStart = () => start().catch(() => { dispose(); });
    if (typeof IntersectionObserver === "undefined") safelyStart();
    else {
      observer = new IntersectionObserver(([entry]) => { if (entry.isIntersecting) { observer.disconnect(); safelyStart(); } }, { rootMargin: "200px" });
      observer.observe(node);
    }
    return () => { cancelled = true; observer?.disconnect(); dispose(); };
  }, [storyRef, reducedMotion]);
  return <div ref={host} className="dependency-field" aria-hidden="true">
    <svg viewBox="0 0 800 440" className="dependency-field__fallback">
      {POINTS.map((point, index) => {
        const branch = index % 3;
        const x = (point.x * 90 + 400) * (1 - progress) + (200 + branch * 200) * progress;
        const y = (point.y * 80 + 220) * (1 - progress) + (index < 3 ? 140 : 190 + Math.floor(index / 3) * 10) * progress;
        return <g key={index}><path d={`M${x},${y} L${400 * (1 - progress) + (200 + branch * 200) * progress},180`} /><circle cx={x} cy={y} r={index < 3 ? 5 + progress * 5 : 3} /></g>;
      })}
    </svg>
    <span className="field-coordinate field-coordinate--top">MANIFEST / DEPENDENCY GRAPH</span>
    <span className="field-coordinate field-coordinate--bottom">47 MATCHES → 3 ACTIONABLE FINDINGS · ILLUSTRATIVE</span>
  </div>;
}
