/* Progressive enhancement only.
 *
 * Every action on this site is a real form that works with JavaScript off. This
 * file adds three courtesies on top: confirmation before a destructive submit,
 * a busy state so a slow scan doesn't look like a dead button, and double-submit
 * prevention. Nothing here is load-bearing.
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
