import { useEffect, useRef } from "react";

const POINTS = Array.from({ length: 47 }, (_, index) => ({
  x: Math.sin(index * 2.399) * (1.1 + (index % 6) * 0.3),
  y: Math.cos(index * 1.719) * (0.7 + (index % 5) * 0.27),
  z: Math.sin(index * 0.91) * 1.2,
}));

// One story-specific WebGL scene. No assets or network requests beyond the
// local Three.js chunk. SVG is the baseline for reduced motion/context loss.
export function DependencyField({ storyRef, progress }) {
  const host = useRef(null);
  const progressRef = useRef(progress);
  useEffect(() => {
    progressRef.current = progress;
    host.current?.dispatchEvent(new Event("graph-update"));
  }, [progress]);
  useEffect(() => {
    const node = host.current;
    const story = storyRef.current;
    if (!window.matchMedia || !window.WebGL2RenderingContext) return;
    const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
    let cancelled = false;
    let generation = 0;
    let dispose = () => {};
    let observer;
    async function start() {
      if (preference.matches || cancelled) return;
      const request = ++generation;
      const THREE = await import("three");
      if (cancelled || preference.matches || request !== generation) return;
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
      function draw() {
        if (lost || cancelled) return;
        const dark = document.documentElement.dataset.theme === "dark";
        const mix = progressRef.current;
        POINTS.forEach((point, index) => {
          const branch = index % 3;
          const rank = Math.floor(index / 3);
          const target = { x: (branch - 1) * 2.2, y: index < 3 ? 0.75 : 0.25 - rank * 0.13, z: index < 3 ? 0.5 : Math.sin(index) * 0.24 };
          object.position.set(point.x + (target.x - point.x) * mix, point.y + (target.y - point.y) * mix, point.z + (target.z - point.z) * mix);
          object.scale.setScalar(index < 3 ? 1 + mix * 1.6 : 1 - mix * 0.7);
          object.updateMatrix(); nodes.setMatrixAt(index, object.matrix);
          color.set(index < 3 ? (index === 1 ? (dark ? "#e9a184" : "#a55734") : (dark ? "#c3d9af" : "#31573a")) : (dark ? "#778f6b" : "#7b8e70"));
          nodes.setColorAt(index, color);
          vertices.set([object.position.x, object.position.y, object.position.z, (branch - 1) * 2.2 * mix, 0.75 * mix, 0], index * 6);
        });
        nodes.instanceMatrix.needsUpdate = true;
        nodes.instanceColor.needsUpdate = true;
        linesGeometry.attributes.position.needsUpdate = true;
        linesMaterial.color.set(dark ? "#b7cfaa" : "#496e39");
        renderer.render(scene, camera);
      }
      function resize() {
        if (!node.clientWidth || !node.clientHeight) return;
        renderer.setSize(node.clientWidth, node.clientHeight);
        camera.aspect = node.clientWidth / node.clientHeight;
        camera.updateProjectionMatrix(); draw();
      }
      function onProgress(event) { progressRef.current = event.detail; draw(); }
      function pointer(event) {
        if (!window.matchMedia("(pointer: fine)").matches) return;
        const rect = node.getBoundingClientRect();
        group.rotation.y = (event.clientX - rect.left - rect.width / 2) / rect.width * 0.2;
        group.rotation.x = (event.clientY - rect.top - rect.height / 2) / rect.height * 0.12;
        draw();
      }
      function reset() { group.rotation.set(0, 0, 0); draw(); }
      function onLost(event) { event.preventDefault(); lost = true; node.dataset.ready = "false"; }
      node.append(renderer.domElement);
      node.dataset.ready = "true";
      renderer.domElement.addEventListener("webglcontextlost", onLost);
      node.addEventListener("pointermove", pointer);
      node.addEventListener("pointerleave", reset);
      node.addEventListener("graph-update", draw);
      story.addEventListener("analysis-progress", onProgress);
      const resizeObserver = new ResizeObserver(resize); resizeObserver.observe(node);
      const themeObserver = new MutationObserver(draw); themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
      resize();
      dispose = () => {
        resizeObserver.disconnect(); themeObserver.disconnect();
        node.removeEventListener("pointermove", pointer); node.removeEventListener("pointerleave", reset); node.removeEventListener("graph-update", draw);
        story.removeEventListener("analysis-progress", onProgress);
        renderer.domElement.removeEventListener("webglcontextlost", onLost);
        geometry.dispose(); material.dispose(); linesGeometry.dispose(); linesMaterial.dispose();
        renderer.dispose(); renderer.forceContextLoss(); renderer.domElement.remove(); node.dataset.ready = "false";
      };
    }
    const safelyStart = () => start().catch(() => { dispose(); });
    function preferenceChanged() { generation++; dispose(); dispose = () => {}; if (!preference.matches) safelyStart(); }
    preference.addEventListener("change", preferenceChanged);
    if (typeof IntersectionObserver === "undefined") safelyStart();
    else {
      observer = new IntersectionObserver(([entry]) => { if (entry.isIntersecting) { observer.disconnect(); safelyStart(); } }, { rootMargin: "200px" });
      observer.observe(node);
    }
    return () => { cancelled = true; observer?.disconnect(); preference.removeEventListener("change", preferenceChanged); dispose(); };
  }, [storyRef]);
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
