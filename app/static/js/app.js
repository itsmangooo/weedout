/* Progressive enhancement only.
 *
 * Every action on this site is a real form that works with JavaScript off, and
 * every destination is a real link. Nothing in this file is load-bearing:
 *
 *   - confirmation before a destructive submit
 *   - a busy state, so a slow scan doesn't look like a dead button
 *   - double-submit prevention
 *   - the sidebar's collapsed state and its mobile drawer (with JS off the
 *     sidebar is simply always open)
 *   - a command palette over the links already on the page (Ctrl/Cmd-K)
 *   - toasts, stashed across the redirect that follows a form post
 *   - copy-to-clipboard buttons
 *   - client-side table sort and filter, on rows already rendered
 *   - the theme switcher (the boot itself is in theme.js, which must run
 *     before first paint)
 *   - keyboard shortcuts and the `?` reference sheet
 *   - live updates over EventSource, where the endpoint is available
 *   - the markdown preview in the docs editor
 *   - scroll reveal on the marketing pages
 *
 * If this file fails to load, the application is less pleasant and entirely
 * usable.
 */

(function () {
  "use strict";

  /* Confirm destructive submits. The prompt text lives on the form, so the
     wording stays next to the thing it describes. */
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    var message = form.dataset.confirm;
    if (message && !window.confirm(message)) {
      event.preventDefault();
      return;
    }

    var submitter = event.submitter;
    if (!(submitter instanceof HTMLButtonElement)) return;

    /* Guard against a double submit while the request is in flight. Disabling
       the button directly would drop its name/value from the payload, so the
       form gets the busy class and the button is disabled on the next tick,
       after serialisation. */
    if (form.dataset.submitting === "true") {
      event.preventDefault();
      return;
    }
    form.dataset.submitting = "true";

    var busyText = submitter.dataset.busyText;
    window.setTimeout(function () {
      form.classList.add("is-busy");
      if (busyText) submitter.textContent = busyText;
      submitter.disabled = true;
    }, 0);
  });

  /* Modal dialogs. Native <dialog> gives us focus trapping, Esc-to-close and
     the backdrop for free; this only wires the open/close buttons. */
  document.addEventListener("click", function (event) {
    var opener = event.target.closest("[data-open-modal]");
    if (opener) {
      var dialog = document.getElementById(opener.dataset.openModal);
      if (dialog && typeof dialog.showModal === "function") {
        event.preventDefault();
        dialog.showModal();
      }
      return;
    }

    var closer = event.target.closest("[data-close-modal]");
    if (closer) {
      event.preventDefault();
      var open = closer.closest("dialog");
      if (open) open.close();
    }
  });

  /* Typed-confirmation inputs: keep the destructive button disabled until the
     value matches exactly. Convenience only — the server checks this too, so
     the guard holds for a hand-crafted POST with no JavaScript involved. */
  document.addEventListener("input", function (event) {
    var input = event.target;
    if (!(input instanceof HTMLInputElement) || !input.dataset.mustEqual) return;

    var button = document.getElementById(input.dataset.enables);
    if (button) {
      button.disabled =
        input.value.trim().toLowerCase() !== input.dataset.mustEqual.trim().toLowerCase();
    }
  });

  /* ---------------------------------------------------------------------
     Markdown preview for the docs editor.

     A deliberately small subset — headings, emphasis, code, links, lists,
     quotes and rules — because this only has to help someone check structure
     while writing. The published page is rendered server-side by the real
     parser, so this approximation is never what ships.

     Everything is escaped first, so a preview can't inject markup into the
     admin page it is rendered on.
     --------------------------------------------------------------------- */

  function escapeHtml(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderInline(text) {
    return text
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(^|[^*])\*([^*]+)\*/g, "$1<em>$2</em>")
      /* Only http(s) and root-relative links become anchors; anything else
         (javascript:, data:) is left as plain text. */
      .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+|\/[^)\s]*)\)/g, '<a href="$2">$1</a>');
  }

  function renderMarkdown(source) {
    var out = [];
    var blocks = escapeHtml(source).split(/\n{2,}/);

    blocks.forEach(function (block) {
      var text = block.trim();
      if (!text) return;

      if (/^```/.test(text)) {
        out.push("<pre><code>" + text.replace(/^```[^\n]*\n?|```$/g, "") + "</code></pre>");
        return;
      }

      var heading = text.match(/^(#{1,4})\s+(.*)$/);
      if (heading) {
        var level = heading[1].length;
        out.push("<h" + level + ">" + renderInline(heading[2]) + "</h" + level + ">");
        return;
      }

      if (/^(-{3,}|\*{3,})$/.test(text)) {
        out.push("<hr>");
        return;
      }

      if (/^>\s/.test(text)) {
        out.push("<blockquote>" + renderInline(text.replace(/^>\s?/gm, "")) + "</blockquote>");
        return;
      }

      var lines = text.split("\n");
      if (lines.every(function (l) { return /^\s*[-*]\s+/.test(l); })) {
        out.push(
          "<ul>" +
            lines.map(function (l) {
              return "<li>" + renderInline(l.replace(/^\s*[-*]\s+/, "")) + "</li>";
            }).join("") +
            "</ul>"
        );
        return;
      }
      if (lines.every(function (l) { return /^\s*\d+\.\s+/.test(l); })) {
        out.push(
          "<ol>" +
            lines.map(function (l) {
              return "<li>" + renderInline(l.replace(/^\s*\d+\.\s+/, "")) + "</li>";
            }).join("") +
            "</ol>"
        );
        return;
      }

      out.push("<p>" + renderInline(text.replace(/\n/g, " ")) + "</p>");
    });

    return out.join("\n");
  }

  function syncPreview(source) {
    var target = document.getElementById(source.dataset.preview);
    if (target) target.innerHTML = renderMarkdown(source.value);
  }

  document.addEventListener("input", function (event) {
    if (event.target instanceof HTMLTextAreaElement && event.target.dataset.preview) {
      syncPreview(event.target);
    }
  });

  document.querySelectorAll("textarea[data-preview]").forEach(syncPreview);

  /* ---------------------------------------------------------------------
     Scroll reveal. Elements marked .reveal fade in once as they enter view.
     Anyone who has asked for reduced motion, or whose browser lacks
     IntersectionObserver, simply gets them visible from the start.
     --------------------------------------------------------------------- */

  var prefersReducedMotion =
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (!prefersReducedMotion && "IntersectionObserver" in window) {
    var armed = document.querySelectorAll(".reveal");

    function revealAll() {
      armed.forEach(function (el) {
        el.classList.add("is-visible");
      });
    }

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target); /* reveal once, never re-hide */
        });
      },
      {
        /* Generous top and bottom margins so an element is already revealed by
           the time it reaches the viewport. A fast scroll, a restored scroll
           position or an anchor jump must not land on a blank screen. */
        rootMargin: "200px 0px 200px 0px",
        threshold: 0,
      }
    );

    armed.forEach(function (el) {
      el.classList.add("reveal--armed");
      observer.observe(el);
    });

    /* Failsafe. An animation is a nicety; the content is not. If anything goes
       wrong with the observer — a browser quirk, a scroll the callback misses —
       everything becomes visible shortly after load regardless. */
    window.setTimeout(revealAll, 3000);
    window.addEventListener("beforeprint", revealAll);
  }


  /* ---------------------------------------------------------------------
     Application shell: sidebar collapse, mobile drawer.

     The collapsed choice is remembered because it is a workspace preference,
     not a per-page one. The drawer deliberately is not remembered: it is a
     transient overlay, and reopening it on every navigation would be a bug.
     --------------------------------------------------------------------- */

  var body = document.body;
  var COLLAPSE_KEY = "weedout:sidebar-collapsed";

  function isDrawerWidth() {
    return window.matchMedia("(max-width: 900px)").matches;
  }

  try {
    if (window.localStorage.getItem(COLLAPSE_KEY) === "1") {
      body.classList.add("is-collapsed");
    }
  } catch (err) {
    /* Storage can be unavailable (private mode, blocked cookies). The sidebar
       just starts expanded, which is the safe default. */
  }

  function labelSidebar() {
    var collapsed = body.classList.contains("is-collapsed");
    document.querySelectorAll(".sidenav__item").forEach(function (item) {
      var label = item.querySelector(".sidenav__label");
      if (!label) return;
      /* When the label is display:none it leaves the accessibility tree too,
         so the name has to come from somewhere else. */
      if (collapsed) {
        item.setAttribute("title", label.textContent.trim());
        item.setAttribute("aria-label", label.textContent.trim());
      } else {
        item.removeAttribute("title");
        item.removeAttribute("aria-label");
      }
    });
    var toggle = document.querySelector("[data-toggle-sidebar]");
    if (toggle) {
      toggle.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
    }
  }

  labelSidebar();

  function closeDrawer() {
    body.classList.remove("is-drawer-open");
    var scrim = document.querySelector(".scrim");
    if (scrim) scrim.hidden = true;
    var opener = document.querySelector("[data-open-drawer]");
    if (opener) {
      opener.setAttribute("aria-expanded", "false");
      opener.focus();
    }
  }

  document.addEventListener("click", function (event) {
    if (event.target.closest("[data-toggle-sidebar]")) {
      body.classList.toggle("is-collapsed");
      labelSidebar();
      try {
        window.localStorage.setItem(
          COLLAPSE_KEY,
          body.classList.contains("is-collapsed") ? "1" : "0"
        );
      } catch (err) {
        /* Not being able to remember the choice is not a reason to refuse it. */
      }
      return;
    }

    if (event.target.closest("[data-open-drawer]")) {
      body.classList.add("is-drawer-open");
      var scrim = document.querySelector(".scrim");
      if (scrim) scrim.hidden = false;
      event.target.closest("[data-open-drawer]").setAttribute("aria-expanded", "true");
      var first = document.querySelector(".sidenav__item");
      if (first) first.focus();
      return;
    }

    if (event.target.closest("[data-close-drawer]")) {
      closeDrawer();
      return;
    }

    /* Following a link from the drawer should close it, or the new page opens
       underneath an overlay nobody asked to keep. */
    if (body.classList.contains("is-drawer-open") && event.target.closest(".sidenav__item")) {
      closeDrawer();
    }
  });

  window.addEventListener("resize", function () {
    if (!isDrawerWidth() && body.classList.contains("is-drawer-open")) closeDrawer();
  });

  /* ---------------------------------------------------------------------
     Command palette.

     The index is built from the links already on the page plus the fixed set
     of destinations in the sidebar. Nothing is fetched: this is a way to reach
     what the server has already sent, not a search API.
     --------------------------------------------------------------------- */

  var palette = document.getElementById("palette");

  if (palette && typeof palette.showModal === "function") {
    var input = document.getElementById("palette-input");
    var results = document.getElementById("palette-results");
    var empty = document.getElementById("palette-empty");
    var index = [];
    var active = 0;

    /* Windows and Linux say Ctrl, macOS says Cmd. Showing the wrong one is a
       small lie that makes the shortcut look broken. */
    var isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
    document.querySelectorAll("[data-cmdk-key]").forEach(function (kbd) {
      kbd.textContent = isMac ? "⌘K" : "Ctrl K";
    });

    function buildIndex() {
      var seen = Object.create(null);
      var out = [];

      function add(name, href, kind) {
        name = (name || "").replace(/\s+/g, " ").trim();
        if (!name || !href || seen[kind + href]) return;
        seen[kind + href] = true;
        out.push({ name: name, href: href, kind: kind });
      }

      document.querySelectorAll(".sidenav__item[data-jump]").forEach(function (a) {
        add(a.dataset.jump, a.getAttribute("href"), "Page");
      });

      /* Projects and findings linked from whatever page you opened the palette
         on. On the dashboard that is every project you have. */
      document.querySelectorAll('.project').forEach(function (a) {
        var name = a.querySelector(".project__name");
        add(name && name.textContent, a.getAttribute("href"), "Project");
      });

      document.querySelectorAll(".finding__link").forEach(function (a) {
        var pkg = a.querySelector(".finding__pkg");
        var cve = a.querySelector(".finding__cve");
        var label = [pkg && pkg.textContent, cve && cve.textContent]
          .filter(Boolean)
          .join(" · ");
        add(label, a.getAttribute("href"), "Finding");
      });

      /* Views of the current project, when there is one. */
      document.querySelectorAll('.tabs a[href*="view="]').forEach(function (a) {
        var head = document.querySelector(".page-head h1");
        add(
          (head ? head.textContent.trim() + " — " : "") + a.textContent,
          a.getAttribute("href"),
          "View"
        );
      });

      return out;
    }

    /* Subsequence match, the standard command-palette behaviour: "chkapi"
       finds "checkout-api". Earlier and tighter matches rank first. */
    function score(name, query) {
      if (!query) return { score: 0, marks: [] };
      var lower = name.toLowerCase();
      var marks = [];
      var at = 0;
      var gaps = 0;
      for (var i = 0; i < query.length; i++) {
        var found = lower.indexOf(query[i], at);
        if (found === -1) return null;
        if (marks.length && found > at) gaps += found - at;
        marks.push(found);
        at = found + 1;
      }
      return { score: marks[0] * 2 + gaps, marks: marks };
    }

    function highlight(name, marks) {
      var out = "";
      var set = Object.create(null);
      marks.forEach(function (m) {
        set[m] = true;
      });
      for (var i = 0; i < name.length; i++) {
        var ch = name[i].replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        out += set[i] ? "<mark>" + ch + "</mark>" : ch;
      }
      return out;
    }

    function render() {
      var query = input.value.trim().toLowerCase();
      var matched = [];

      index.forEach(function (item) {
        var hit = score(item.name, query);
        if (hit) matched.push({ item: item, score: hit.score, marks: hit.marks });
      });

      matched.sort(function (a, b) {
        return a.score - b.score || a.item.name.length - b.item.name.length;
      });
      matched = matched.slice(0, 30);

      results.innerHTML = "";
      matched.forEach(function (entry, i) {
        var li = document.createElement("li");
        var a = document.createElement("a");
        a.className = "palette__option";
        a.href = entry.item.href;
        a.setAttribute("role", "option");
        a.setAttribute("aria-selected", i === active ? "true" : "false");
        a.innerHTML =
          '<span class="palette__name">' +
          highlight(entry.item.name, entry.marks) +
          '</span><span class="palette__kind">' +
          entry.item.kind +
          "</span>";
        li.appendChild(a);
        results.appendChild(li);
      });

      empty.hidden = matched.length > 0;
      results.hidden = matched.length === 0;
    }

    function move(step) {
      var options = results.querySelectorAll(".palette__option");
      if (!options.length) return;
      active = (active + step + options.length) % options.length;
      options.forEach(function (o, i) {
        o.setAttribute("aria-selected", i === active ? "true" : "false");
      });
      options[active].scrollIntoView({ block: "nearest" });
    }

    function openPalette() {
      index = buildIndex();
      input.value = "";
      active = 0;
      render();
      palette.showModal();
      input.focus();
    }

    document.addEventListener("click", function (event) {
      if (event.target.closest("[data-open-palette]")) {
        event.preventDefault();
        openPalette();
      }
    });

    document.addEventListener("keydown", function (event) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        if (palette.open) {
          palette.close();
        } else {
          openPalette();
        }
        return;
      }

      if (!palette.open) return;

      if (event.key === "ArrowDown") {
        event.preventDefault();
        move(1);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        move(-1);
      } else if (event.key === "Enter") {
        var chosen = results.querySelectorAll(".palette__option")[active];
        if (chosen) {
          event.preventDefault();
          window.location.href = chosen.getAttribute("href");
        }
      }
    });

    input.addEventListener("input", function () {
      active = 0;
      render();
    });

    /* Clicking the backdrop closes it; clicking the panel must not. */
    palette.addEventListener("click", function (event) {
      if (event.target === palette) palette.close();
    });
  }

  /* ---------------------------------------------------------------------
     Toasts.

     Actions here are real form posts that redirect, so the confirmation has to
     survive a navigation. The message is stashed on submit and shown once the
     next page loads — no route, no flash cookie, no change to any handler.
     --------------------------------------------------------------------- */

  var TOAST_KEY = "weedout:toast";

  function toast(message, kind) {
    var host = document.getElementById("toasts");
    if (!host || !message) return;

    var el = document.createElement("div");
    el.className = "toast" + (kind === "error" ? " toast--error" : "");
    el.innerHTML =
      '<span class="toast__dot" aria-hidden="true"></span>' +
      '<span class="toast__text"></span>' +
      '<button class="toast__close" type="button" aria-label="Dismiss">×</button>';
    el.querySelector(".toast__text").textContent = message;
    host.appendChild(el);

    var timer = window.setTimeout(dismiss, 4200);

    function dismiss() {
      window.clearTimeout(timer);
      el.classList.add("is-leaving");
      el.addEventListener("animationend", function () {
        el.remove();
      });
    }

    el.querySelector(".toast__close").addEventListener("click", dismiss);
  }

  window.weedoutToast = toast;

  try {
    var pending = window.sessionStorage.getItem(TOAST_KEY);
    if (pending) {
      window.sessionStorage.removeItem(TOAST_KEY);
      toast(pending);
    }
  } catch (err) {
    /* No session storage means no cross-navigation toast. The page still
       renders its own notice, which is the thing that actually matters. */
  }

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.dataset.toast) return;
    try {
      window.sessionStorage.setItem(TOAST_KEY, form.dataset.toast);
    } catch (err) {
      /* Ignored for the same reason as above. */
    }
  });

  /* ---------------------------------------------------------------------
     Copy to clipboard.
     --------------------------------------------------------------------- */

  document.addEventListener("click", function (event) {
    var button = event.target.closest(".copy");
    if (!button) return;
    event.preventDefault();
    event.stopPropagation();

    var text = button.dataset.copy;
    if (!text) {
      var host = button.closest("[data-copy-source]");
      if (host) text = host.dataset.copySource;
    }
    if (!text) return;

    function done() {
      button.classList.add("is-done");
      var label = button.getAttribute("aria-label");
      button.setAttribute("aria-label", "Copied");
      window.setTimeout(function () {
        button.classList.remove("is-done");
        if (label) button.setAttribute("aria-label", label);
      }, 1400);
      toast("Copied " + text.slice(0, 60));
    }

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }

    /* http://localhost is a secure context, but a tunnelled or plain-http
       deployment is not, and there the async clipboard API is unavailable. */
    function fallback() {
      var scratch = document.createElement("textarea");
      scratch.value = text;
      scratch.setAttribute("readonly", "");
      scratch.style.position = "fixed";
      scratch.style.opacity = "0";
      document.body.appendChild(scratch);
      scratch.select();
      try {
        document.execCommand("copy");
        done();
      } catch (err) {
        toast("Couldn't copy — select it and press " + (isMacLike() ? "⌘C" : "Ctrl+C"), "error");
      }
      scratch.remove();
    }

    function isMacLike() {
      return /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
    }
  });

  /* ---------------------------------------------------------------------
     Sortable, filterable tables.

     Operates on rows already in the document. `data-sort-value` wins over the
     cell text where the two differ — "3m ago" sorts by its timestamp, not
     alphabetically, which is the whole reason the attribute exists.
     --------------------------------------------------------------------- */

  function cellValue(row, column) {
    var cell = row.children[column];
    if (!cell) return "";
    return cell.dataset.sortValue !== undefined ? cell.dataset.sortValue : cell.textContent.trim();
  }

  document.addEventListener("click", function (event) {
    var th = event.target.closest("th[data-sort]");
    if (!th) return;

    var table = th.closest("table");
    var head = th.parentElement;
    var column = Array.prototype.indexOf.call(head.children, th);
    var tbody = table.tBodies[0];
    if (!tbody) return;

    var ascending = th.getAttribute("aria-sort") !== "ascending";

    Array.prototype.forEach.call(head.children, function (cell) {
      cell.removeAttribute("aria-sort");
    });
    th.setAttribute("aria-sort", ascending ? "ascending" : "descending");

    var rows = Array.prototype.slice.call(tbody.rows);
    var numeric = rows.every(function (row) {
      var v = cellValue(row, column);
      return v === "" || v === "—" || !isNaN(Number(v));
    });

    rows.sort(function (a, b) {
      var av = cellValue(a, column);
      var bv = cellValue(b, column);
      if (numeric) return (Number(av) || 0) - (Number(bv) || 0);
      return av.localeCompare(bv, undefined, { numeric: true, sensitivity: "base" });
    });

    if (!ascending) rows.reverse();
    rows.forEach(function (row) {
      tbody.appendChild(row);
    });
  });

  document.addEventListener("input", function (event) {
    var field = event.target;
    if (!field.classList || !field.classList.contains("table-filter__input")) return;

    var scope = document.getElementById(field.dataset.filters);
    if (!scope) return;

    var query = field.value.trim().toLowerCase();
    var rows = scope.matches("table") ? scope.tBodies[0].rows : scope.children;
    var shown = 0;

    Array.prototype.forEach.call(rows, function (row) {
      var hit = !query || row.textContent.toLowerCase().indexOf(query) !== -1;
      row.hidden = !hit;
      if (hit) shown++;
    });

    var count = document.getElementById(field.dataset.count);
    if (count) {
      count.textContent = query
        ? shown + " of " + rows.length
        : rows.length + " " + (rows.length === 1 ? "row" : "rows");
    }
  });

  /* ---------------------------------------------------------------------
     Scan in progress.

     `data-busy-text` already covers the button. This adds the running
     indicator beside it, so the wait reads as work rather than as a page that
     stopped responding.
     --------------------------------------------------------------------- */

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.dataset.scanning) return;

    var host = document.getElementById(form.dataset.scanning);
    if (host) host.hidden = false;
  });


  /* ---------------------------------------------------------------------
     Theme.

     Two independent preferences, for two different questions:

       theme   light | dark | system   whether you want dark at all
       preset  carbon | midnight | ash which dark, when dark is on

     Keeping them apart means someone on "follow the system" can still choose
     their preset, ready for the moment the system flips — picking one does not
     quietly pin them out of system mode.
     --------------------------------------------------------------------- */

  var THEME_KEY = "weedout:theme";
  var DARK_KEY = "weedout:dark";
  var DARK_PRESETS = ["carbon", "midnight", "ash"];

  function readStored(key, allowed, fallback) {
    try {
      var value = window.localStorage.getItem(key);
      if (allowed.indexOf(value) !== -1) return value;
    } catch (err) {
      /* Storage blocked; treat it as no saved choice. */
    }
    return fallback;
  }

  function currentTheme() {
    return readStored(THEME_KEY, ["light", "dark"], "system");
  }

  function currentPreset() {
    return readStored(DARK_KEY, DARK_PRESETS, "carbon");
  }

  function store(key, value) {
    try {
      if (value === null) {
        window.localStorage.removeItem(key);
      } else {
        window.localStorage.setItem(key, value);
      }
    } catch (err) {
      /* The choice still applies to this page; it just will not persist. */
    }
  }

  function paintThemer() {
    var theme = currentTheme();
    var preset = currentPreset();
    document.querySelectorAll("[data-theme-set]").forEach(function (button) {
      button.setAttribute("aria-pressed", button.dataset.themeSet === theme ? "true" : "false");
    });
    document.querySelectorAll("[data-dark-set]").forEach(function (button) {
      button.setAttribute("aria-pressed", button.dataset.darkSet === preset ? "true" : "false");
    });
  }

  /* Changing theme repaints every colour at once. Without suppressing
     transitions for a frame the whole page animates through the change, which
     reads as a rendering glitch rather than as a setting taking effect. */
  function withoutTransitions(apply) {
    var root = document.documentElement;
    root.classList.add("theme-switching");
    apply(root);
    paintThemer();
    window.requestAnimationFrame(function () {
      window.requestAnimationFrame(function () {
        root.classList.remove("theme-switching");
      });
    });
  }

  function setTheme(choice) {
    withoutTransitions(function (root) {
      if (choice === "system") {
        root.removeAttribute("data-theme");
        store(THEME_KEY, null);
      } else {
        root.setAttribute("data-theme", choice);
        store(THEME_KEY, choice);
      }
    });
  }

  function setPreset(choice) {
    withoutTransitions(function (root) {
      if (choice === "carbon") {
        /* Carbon is what :root already is, so it is the absence of the
           attribute rather than a value — one less thing that can disagree
           with the stylesheet. */
        root.removeAttribute("data-dark");
        store(DARK_KEY, null);
      } else {
        root.setAttribute("data-dark", choice);
        store(DARK_KEY, choice);
      }

      /* Picking a dark preset while in light mode would otherwise change
         nothing visible, which reads as a broken control. Choosing a dark
         means you want to see it. */
      if (currentTheme() === "light") {
        root.setAttribute("data-theme", "dark");
        store(THEME_KEY, "dark");
      }
    });
  }

  document.addEventListener("click", function (event) {
    var themeButton = event.target.closest("[data-theme-set]");
    if (themeButton) {
      setTheme(themeButton.dataset.themeSet);
      return;
    }
    var presetButton = event.target.closest("[data-dark-set]");
    if (presetButton) setPreset(presetButton.dataset.darkSet);
  });

  paintThemer();

  /* ---------------------------------------------------------------------
     Keyboard shortcuts.

     Every shortcut here is listed in the `?` sheet, and every row in that
     sheet works. They are all ignored while a field has focus, so typing "g"
     into a filter box does not navigate away mid-word.
     --------------------------------------------------------------------- */

  var shortcuts = document.getElementById("shortcuts");
  var pendingGo = false;
  var pendingGoTimer = null;

  function isTyping(target) {
    if (!target) return false;
    if (target.isContentEditable) return true;
    var tag = target.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
  }

  function anyDialogOpen() {
    return !!document.querySelector("dialog[open]");
  }

  document.addEventListener("keydown", function (event) {
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    if (isTyping(event.target)) return;

    /* `?` is Shift+/ on most layouts, so match the produced character rather
       than a key code. */
    if (event.key === "?") {
      event.preventDefault();
      if (shortcuts && typeof shortcuts.showModal === "function") {
        if (shortcuts.open) {
          shortcuts.close();
        } else {
          if (anyDialogOpen()) return;
          shortcuts.showModal();
        }
      }
      return;
    }

    if (anyDialogOpen()) return;

    if (event.key === "[") {
      event.preventDefault();
      var toggle = document.querySelector("[data-toggle-sidebar]");
      if (toggle) toggle.click();
      return;
    }

    /* Two-key sequences, the convention every tool with a `g` prefix uses.
       The window is short so a stray `g` does not lie in wait. */
    if (pendingGo) {
      var routes = { d: "/dashboard", a: "/alerts", p: "/targets/new", s: "/settings" };
      var destination = routes[event.key.toLowerCase()];
      pendingGo = false;
      window.clearTimeout(pendingGoTimer);
      if (destination) {
        event.preventDefault();
        window.location.href = destination;
      }
      return;
    }

    if (event.key.toLowerCase() === "g") {
      pendingGo = true;
      pendingGoTimer = window.setTimeout(function () {
        pendingGo = false;
      }, 1200);
    }
  });

  if (shortcuts) {
    shortcuts.addEventListener("click", function (event) {
      if (event.target === shortcuts) shortcuts.close();
    });
  }

  /* ---------------------------------------------------------------------
     Live updates.

     An EventSource onto /events. The server pushes feed health and the open
     alert count; nothing here polls. If the stream is unavailable — an old
     browser, a proxy that buffers, the endpoint disabled — the page is
     exactly the server-rendered page it already was, which is why none of
     this is load-bearing.
     --------------------------------------------------------------------- */

  var live = document.querySelector("[data-live]");

  if (live && "EventSource" in window) {
    var source = new EventSource("/events");
    var indicator = document.getElementById("live-indicator");

    function markLive(state) {
      if (!indicator) return;
      indicator.dataset.state = state;
      indicator.title =
        state === "on" ? "Live — updates arrive as they happen" : "Not live; reload to refresh";
    }

    source.addEventListener("open", function () {
      markLive("on");
    });

    source.addEventListener("error", function () {
      /* EventSource reconnects on its own; this only reflects the current
         state so the dot never claims to be live while it is not. */
      markLive("off");
    });

    /* Each payload names the elements it updates, so adding a live figure is
       a template change rather than a change here. */
    source.addEventListener("stats", function (event) {
      var data;
      try {
        data = JSON.parse(event.data);
      } catch (err) {
        return;
      }

      Object.keys(data).forEach(function (key) {
        document.querySelectorAll('[data-live-field="' + key + '"]').forEach(function (el) {
          var next = String(data[key]);
          if (el.textContent.trim() === next) return;
          el.textContent = next;
          /* A brief pulse, so a number that changed while you were looking at
             something else does not change in silence. */
          el.classList.remove("is-updated");
          void el.offsetWidth;
          el.classList.add("is-updated");
        });
      });

      if (data._banner) {
        var banner = document.getElementById("live-banner");
        if (banner) {
          banner.querySelector("[data-live-banner-text]").textContent = data._banner;
          banner.hidden = false;
        }
      }
    });

    window.addEventListener("beforeunload", function () {
      source.close();
    });
  }

  /* Restore forms when the browser serves a cached page on back-navigation,
     which would otherwise leave every button stuck in its busy state. */
  window.addEventListener("pageshow", function (event) {
    if (!event.persisted) return;
    document.querySelectorAll("form[data-submitting]").forEach(function (form) {
      delete form.dataset.submitting;
      form.classList.remove("is-busy");
      form.querySelectorAll("button[disabled]").forEach(function (button) {
        button.disabled = false;
      });
    });
  });
})();
