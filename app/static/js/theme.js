/* Theme boot.
 *
 * Loaded synchronously in <head>, ahead of the deferred application bundle,
 * because it has to run before the first paint: applying a saved theme after
 * the stylesheet has painted shows one frame of the wrong one.
 *
 * It is a separate file rather than an inline <script> so that
 * `script-src 'self'` stays strict — no nonce, no hash, no 'unsafe-inline'.
 *
 * Two independent preferences:
 *
 *   weedout:theme  "light" | "dark"        absent = follow the system
 *   weedout:dark   "midnight" | "ash"      absent = carbon, the default preset
 *
 * They are separate because they answer different questions. The preset is
 * which dark you like; the theme is whether you want dark at all. Someone on
 * "follow the system" still has a preset waiting for the moment their system
 * goes dark, and picking one should not silently pin them out of system mode.
 */
(function () {
  "use strict";

  var root = document.documentElement;

  function saved(key) {
    try {
      return localStorage.getItem(key);
    } catch (err) {
      /* Storage blocked (private mode, blocked cookies). Fall through to the
         system preference, which is the sensible default. */
      return null;
    }
  }

  var theme = saved("weedout:theme");
  if (theme === "light" || theme === "dark") {
    root.setAttribute("data-theme", theme);
  }

  var preset = saved("weedout:dark");
  if (preset === "midnight" || preset === "ash") {
    root.setAttribute("data-dark", preset);
  }
})();
