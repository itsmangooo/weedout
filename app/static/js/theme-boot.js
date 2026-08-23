/* Apply the reader's theme before the first paint.
 *
 * Loaded synchronously from <head>, ahead of the stylesheet, so the page is
 * painted once in the right palette. Deferring it — or doing this from React —
 * shows a flash of the other theme on every load, which is worst exactly where
 * it is most visible: somebody who chose dark, loading a page whose default is
 * cream.
 *
 * A separate file rather than an inline block because the CSP is
 * `script-src 'self'` and there is no room for one.
 *
 * This resolves "match system" itself and writes a concrete value, rather than
 * leaving it to a `prefers-color-scheme` rule. Light is the product's default,
 * not a fallback: a reader on a dark machine who has said nothing still gets
 * the design, and one who has said "light" is not overruled by their OS.
 *
 * Deliberately tiny and dependency-free. It runs before anything else on every
 * page load, so it must not be able to fail: a private-mode browser that
 * throws on localStorage should get the default theme, not a blank page.
 */
(function () {
  var STORAGE_KEY = "weedout-theme";

  var choice = null;
  try {
    choice = window.localStorage.getItem(STORAGE_KEY);
  } catch (error) {
    /* Storage is unavailable — Safari private mode, a locked-down profile, an
       embedded webview. The default is a fine answer. */
  }

  var theme = "light";

  if (choice === "dark") {
    theme = "dark";
  } else if (choice === "system") {
    try {
      if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
        theme = "dark";
      }
    } catch (error) {
      /* No matchMedia. Light, as if they had never chosen. */
    }
  }

  document.documentElement.setAttribute("data-theme", theme);
})();
