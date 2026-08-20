/* The CLI page's hero visual.
 *
 * Raw WebGL, no library. Three.js would be ~150KB gzipped to draw two
 * triangles and a fragment shader — the whole scene is a full-screen quad, so
 * a scene graph, a camera and a material system are all overhead. This is
 * about 120 lines and one shader.
 *
 * What it draws: a field of drifting points, most of them dim, a few lit. It
 * is the product's argument as a picture — thousands of advisories, a handful
 * that matter — rather than decoration that happens to be on a security site.
 *
 * Nothing here is load-bearing. The canvas sits behind real text in normal
 * document flow; if WebGL is unavailable, the context is lost, or reduced
 * motion is requested, the canvas stays blank or frozen and the page reads
 * exactly the same.
 */
(function () {
  "use strict";

  var canvas = document.getElementById("cli-hero-canvas");
  if (!canvas) return;

  var reduceMotion =
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var gl =
    canvas.getContext("webgl", { alpha: true, antialias: true, powerPreference: "low-power" }) ||
    canvas.getContext("experimental-webgl", { alpha: true });

  if (!gl) {
    // No WebGL. The heading and the install command are real DOM above this;
    // a missing background is not a broken page.
    canvas.setAttribute("data-fallback", "true");
    return;
  }

  var VERTEX = [
    "attribute vec2 a_seed;",
    "attribute float a_kind;",
    "uniform float u_time;",
    "uniform vec2 u_resolution;",
    "varying float v_kind;",
    "varying float v_fade;",
    "",
    "void main() {",
    // Rising embers. The previous values (0.03 to 0.08) crossed the hero in
    // twelve to thirty-three seconds -- one to three pixels a second, which is
    // motion in the arithmetic and stillness to anybody looking at it. These
    // cross in five to nine, which reads as drift without pulling the eye off
    // the headline.
    "  float speed = 0.11 + a_seed.y * 0.09;",
    // Drift upward and wrap, so the field never empties.
    "  float y = fract(a_seed.y + u_time * speed);",
    // A slow lateral sway so the field does not read as a rising grid. The
    // period was forty-two seconds, which is to say invisible; this is twelve.
    "  float x = a_seed.x + sin((u_time * 0.5) + a_seed.y * 6.2831) * 0.025;",
    "  vec2 pos = vec2(x, y) * 2.0 - 1.0;",
    // Correct for viewport aspect so points stay round.
    "  gl_Position = vec4(pos, 0.0, 1.0);",
    "  v_kind = a_kind;",
    // Fade in at the bottom and out at the top; nothing pops in or out.
    "  v_fade = smoothstep(0.0, 0.15, y) * (1.0 - smoothstep(0.8, 1.0, y));",
    "  gl_PointSize = (a_kind > 0.5 ? 3.5 : 1.8) * (u_resolution.y / 900.0 + 0.6);",
    "}",
  ].join("\n");

  var FRAGMENT = [
    "precision mediump float;",
    "uniform vec3 u_accent;",
    "uniform vec3 u_quiet;",
    "varying float v_kind;",
    "varying float v_fade;",
    "",
    "void main() {",
    // Round the square point sprite into a soft disc.
    "  vec2 d = gl_PointCoord - vec2(0.5);",
    "  float r = length(d);",
    "  if (r > 0.5) discard;",
    "  float alpha = (1.0 - smoothstep(0.2, 0.5, r)) * v_fade;",
    "  vec3 colour = mix(u_quiet, u_accent, v_kind);",
    "  alpha *= mix(0.30, 0.95, v_kind);",
    "  gl_FragColor = vec4(colour, alpha);",
    "}",
  ].join("\n");

  function compile(type, source) {
    var shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      return null;
    }
    return shader;
  }

  var vs = compile(gl.VERTEX_SHADER, VERTEX);
  var fs = compile(gl.FRAGMENT_SHADER, FRAGMENT);
  if (!vs || !fs) {
    canvas.setAttribute("data-fallback", "true");
    return;
  }

  var program = gl.createProgram();
  gl.attachShader(program, vs);
  gl.attachShader(program, fs);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    canvas.setAttribute("data-fallback", "true");
    return;
  }
  gl.useProgram(program);

  // The ratio is the point: most advisories are noise, a few are not.
  var COUNT = 900;
  var LIT_RATIO = 0.06;

  var seeds = new Float32Array(COUNT * 2);
  var kinds = new Float32Array(COUNT);
  for (var i = 0; i < COUNT; i++) {
    seeds[i * 2] = Math.random();
    seeds[i * 2 + 1] = Math.random();
    kinds[i] = Math.random() < LIT_RATIO ? 1.0 : 0.0;
  }

  function buffer(data, location, size) {
    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
    var loc = gl.getAttribLocation(program, location);
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, size, gl.FLOAT, false, 0, 0);
  }

  buffer(seeds, "a_seed", 2);
  buffer(kinds, "a_kind", 1);

  var uTime = gl.getUniformLocation(program, "u_time");
  var uResolution = gl.getUniformLocation(program, "u_resolution");
  var uAccent = gl.getUniformLocation(program, "u_accent");
  var uQuiet = gl.getUniformLocation(program, "u_quiet");

  /* Colours come from the stylesheet, not from constants here, so the hero
     follows the theme and every preset without this file knowing they exist. */
  function readToken(name, fallback) {
    var raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    var probe = document.createElement("div");
    probe.style.color = raw || fallback;
    document.body.appendChild(probe);
    var resolved = getComputedStyle(probe).color;
    probe.remove();
    var match = resolved.match(/[\d.]+/g);
    if (!match) return [0.57, 0.47, 1.0];
    return [match[0] / 255, match[1] / 255, match[2] / 255];
  }

  function applyColours() {
    var accent = readToken("--accent", "#9179ff");
    var quiet = readToken("--text-dim", "#8f8fa4");
    gl.uniform3f(uAccent, accent[0], accent[1], accent[2]);
    gl.uniform3f(uQuiet, quiet[0], quiet[1], quiet[2]);
  }

  gl.enable(gl.BLEND);
  gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

  function resize() {
    // Cap the device pixel ratio: a 3x phone would be rendering nine times the
    // pixels for a background, which is where a hero like this drains a
    // battery for nothing.
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var width = Math.floor(canvas.clientWidth * dpr);
    var height = Math.floor(canvas.clientHeight * dpr);
    if (canvas.width === width && canvas.height === height) return;
    canvas.width = width;
    canvas.height = height;
    gl.viewport(0, 0, width, height);
    gl.uniform2f(uResolution, width, height);
  }

  applyColours();
  resize();
  window.addEventListener("resize", resize);

  /* A deferred script runs before layout has necessarily settled, so the first
     measurement can legitimately be 0×0. A ResizeObserver fires once the
     element actually has a box — and again whenever it changes, which also
     covers the window being resized and the sidebar collapsing beside it. */
  if (window.ResizeObserver) {
    new ResizeObserver(resize).observe(canvas);
  } else {
    // Older browsers: try again after layout.
    requestAnimationFrame(resize);
  }

  // Repaint the palette when the theme changes, without polling for it.
  if (window.MutationObserver) {
    new MutationObserver(applyColours).observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme", "data-dark"],
    });
  }

  var start = performance.now();
  var running = true;

  function frame(now) {
    if (!running) return;
    if (canvas.width === 0 || canvas.height === 0) {
      requestAnimationFrame(frame);
      return;
    }
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.uniform1f(uTime, (now - start) / 1000);
    gl.drawArrays(gl.POINTS, 0, COUNT);
    requestAnimationFrame(frame);
  }

  if (reduceMotion) {
    // One frame, held. The composition is still there; nothing moves.
    gl.uniform1f(uTime, 0);
    gl.drawArrays(gl.POINTS, 0, COUNT);
  } else {
    requestAnimationFrame(frame);
  }

  /* Stop when the tab is hidden. A background canvas spinning in a tab nobody
     is looking at is pure battery cost. */
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      running = false;
    } else if (!reduceMotion) {
      running = true;
      start = performance.now() - 1;
      requestAnimationFrame(frame);
    }
  });

  canvas.addEventListener("webglcontextlost", function (event) {
    // Losing the context is normal on a laptop that sleeps. Prevent the
    // default so the browser will hand it back, and stop drawing meanwhile.
    event.preventDefault();
    running = false;
  });
})();
