/* Marketing-page motion: the scripted demo, 3D tilt, and parallax.
 *
 * Only loaded on the landing and CLI pages. The application pages keep their
 * lean bundle — none of this ships to somebody using the product.
 *
 * Everything here is decorative and every piece degrades to "nothing moves".
 * The demo is aria-hidden and the prose beside it makes the same argument in
 * words, so a visitor who never sees a single frame of it loses no information.
 */
(function () {
  "use strict";

  var reduceMotion =
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------------------------------------------------------------------
     The scripted dashboard.

     A queue of steps, each one moving the cursor to a real element and then
     doing something to the interface. Written as data rather than as a chain
     of callbacks so the sequence can be read top to bottom, and so a step can
     be added without rewiring the timing of the ones after it.
     --------------------------------------------------------------------- */

  function runDemo(stage) {
    var win = stage.querySelector(".appwin");
    var cursor = stage.querySelector("[data-cursor]");
    var caption = stage.querySelector("[data-caption]");
    if (!win || !cursor) return;

    var counts = {
      open: stage.querySelector('[data-count="open"]'),
      filtered: stage.querySelector('[data-count="filtered"]'),
      dismissed: stage.querySelector('[data-count="dismissed"]'),
    };

    var timers = [];
    function after(ms, fn) {
      timers.push(window.setTimeout(fn, ms));
    }
    function clearAll() {
      timers.forEach(window.clearTimeout);
      timers = [];
    }

    /* Move to an element's centre, in the frame's own coordinates. Measured
       every time rather than cached: the frame is tilted and can be resized,
       and a cached position would drift away from what it points at. */
    function moveTo(target, then) {
      if (!target) return then && then();
      var frame = win.getBoundingClientRect();
      var box = target.getBoundingClientRect();
      cursor.style.left = box.left - frame.left + box.width / 2 + "px";
      cursor.style.top = box.top - frame.top + box.height / 2 + "px";
      cursor.classList.add("is-visible");
      after(620, then || function () {});
    }

    function click(then) {
      cursor.classList.add("is-clicking");
      after(220, function () {
        cursor.classList.remove("is-clicking");
        if (then) then();
      });
    }

    function say(text) {
      if (!caption) return;
      caption.classList.add("is-changing");
      after(180, function () {
        caption.textContent = text;
        caption.classList.remove("is-changing");
      });
    }

    /* Counting rather than snapping. A number that jumps has changed; a number
       that counts has been *worked on*, which is what the cursor is doing. */
    function countTo(el, target) {
      if (!el) return;
      var from = parseInt(el.textContent, 10);
      if (isNaN(from) || from === target) {
        el.textContent = String(target);
        return;
      }
      var step = from < target ? 1 : -1;
      var value = from;
      var tick = window.setInterval(function () {
        value += step;
        el.textContent = String(value);
        el.classList.add("is-bumped");
        window.setTimeout(function () {
          el.classList.remove("is-bumped");
        }, 200);
        if (value === target) window.clearInterval(tick);
      }, 160);
      timers.push(tick);
    }

    function reset() {
      clearAll();
      cursor.classList.remove("is-visible", "is-clicking");
      stage.querySelectorAll(".appwin__row").forEach(function (row) {
        row.classList.remove("is-leaving", "is-focused");
        row.hidden = false;
      });
      showPanel("open");
      counts.open.textContent = "3";
      counts.filtered.textContent = "47";
      counts.dismissed.textContent = "0";
      say("Three findings cleared the bar. Forty-seven did not.");
    }

    function showPanel(name) {
      stage.querySelectorAll("[data-panel]").forEach(function (panel) {
        panel.hidden = panel.dataset.panel !== name;
      });
      stage.querySelectorAll("[data-tab]").forEach(function (tab) {
        tab.classList.toggle("is-active", tab.dataset.tab === name);
      });
    }

    var kevRow = stage.querySelector('[data-row="kev"]');
    var dismiss = stage.querySelector("[data-act]");
    var filteredTab = stage.querySelector('[data-tab="filtered"]');
    var openTab = stage.querySelector('[data-tab="open"]');

    /* The sequence. Read it as a story: look at the worst one, deal with it,
       then go and check the work the filter did on your behalf. */
    function cycle() {
      reset();

      after(900, function () {
        say("The one being exploited right now leads.");
        moveTo(kevRow, function () {
          kevRow.classList.add("is-focused");

          after(1100, function () {
            say("Dismiss it and the count moves.");
            moveTo(dismiss, function () {
              click(function () {
                kevRow.classList.add("is-leaving");
                countTo(counts.open, 2);
                countTo(counts.dismissed, 1);

                after(700, function () {
                  kevRow.hidden = true;
                  kevRow.classList.remove("is-focused");

                  after(600, function () {
                    say("And everything it decided not to send you is still here.");
                    moveTo(filteredTab, function () {
                      click(function () {
                        showPanel("filtered");

                        after(2600, function () {
                          moveTo(openTab, function () {
                            click(function () {
                              showPanel("open");
                              after(1400, cycle);
                            });
                          });
                        });
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    }

    /* Only runs while it is on screen. A demo animating in a tab nobody is
       looking at is pure battery cost, and the loop would be halfway through
       its story by the time anyone scrolled to it. */
    var running = false;
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting && !running) {
              running = true;
              cycle();
            } else if (!entry.isIntersecting && running) {
              running = false;
              clearAll();
            }
          });
        },
        { threshold: 0.25 }
      ).observe(stage);
    } else {
      cycle();
    }

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        clearAll();
        running = false;
      }
    });
  }


  /* ---------------------------------------------------------------------
     The typing terminal, for the CLI page.

     A script of lines, each either typed a character at a time or printed
     whole. Commands get typed because that is the part a visitor is imagining
     themselves doing; output gets printed because watching a machine
     "type" its own results is a lie about how software works.
     --------------------------------------------------------------------- */

  /* The transcript, shared by both paths: typed when motion is welcome,
     printed at once when it is not. One copy, so the two can never disagree
     about what the command prints.

     cls: a span class for the line; wait: pause after it, in ms. */
  var TERMINAL_SCRIPT = [
      { type: "$ weedout scan", cls: "termwin__cmd", typed: true, wait: 700 },
      { type: "", wait: 260 },
      { type: "acme-storefront  package-lock.json", cls: "termwin__strong", wait: 120 },
      { type: "312 dependencies scanned · 47 filtered out as noise", cls: "termwin__dim", wait: 420 },
      { type: "", wait: 160 },
      { type: "  1 exploited  ·  2 critical  ·  5 high", cls: "termwin__crit", wait: 380 },
      { type: "", wait: 160 },
      { type: "  ! systeminformation@5.0.0  CVE-2021-21315  → 5.3.1", cls: "termwin__crit", wait: 200 },
      { type: "  • minimist@1.2.0  CVE-2021-44906  → 1.2.6", cls: "termwin__warn", wait: 200 },
      { type: "  • lodash@4.17.15  CVE-2021-23337  → 4.17.21", cls: "termwin__warn", wait: 700 },
      { type: "", wait: 200 },
      {
        type: "$ weedout scan --ci",
        cls: "termwin__cmd",
        typed: true,
        wait: 600,
        caption: "In CI, it fails the build only for what is genuinely urgent.",
      },
      { type: "Failing: 3 finding(s) at critical severity or confirmed exploitation.", cls: "termwin__crit", wait: 260 },
    { type: "$ echo $?", cls: "termwin__cmd", typed: true, wait: 200 },
    { type: "1", wait: 2600 },
  ];

  /* One line, with its colour. Used by both paths. */
  function terminalLine(out, text, cls) {
    var span = document.createElement("span");
    if (cls) span.className = cls;
    span.textContent = text + "\n";
    out.appendChild(span);
    return span;
  }

  function runTerminal(stage) {
    var out = stage.querySelector("[data-term-out]");
    var caption = stage.querySelector("[data-term-caption]");
    if (!out) return;

    var script = TERMINAL_SCRIPT;
    var timers = [];
    function after(ms, fn) {
      timers.push(window.setTimeout(fn, ms));
    }
    function clearAll() {
      timers.forEach(window.clearTimeout);
      timers = [];
    }

    function line(text, cls) {
      return terminalLine(out, text, cls);
    }

    /* Typing speed is jittered. A perfectly even interval reads as a
       teleprinter; a little variance reads as hands. */
    function typeLine(text, cls, then) {
      var span = line("", cls);
      var i = 0;
      (function tick() {
        span.textContent = text.slice(0, ++i);
        if (i < text.length) {
          after(26 + Math.random() * 34, tick);
        } else {
          span.textContent = text + "\n";
          then();
        }
      })();
    }

    function play(index) {
      if (index >= script.length) {
        after(600, function () {
          out.textContent = "";
          if (caption) {
            caption.textContent =
              "One command. It reads your lockfile and asks what actually matters.";
          }
          play(0);
        });
        return;
      }

      var step = script[index];
      if (step.caption && caption) caption.textContent = step.caption;

      function next() {
        after(step.wait || 120, function () {
          play(index + 1);
        });
      }

      if (step.typed) {
        typeLine(step.type, step.cls, next);
      } else {
        line(step.type, step.cls);
        next();
      }
    }

    var running = false;
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting && !running) {
              running = true;
              out.textContent = "";
              play(0);
            } else if (!entry.isIntersecting && running) {
              running = false;
              clearAll();
            }
          });
        },
        { threshold: 0.3 }
      ).observe(stage);
    } else {
      play(0);
    }

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        clearAll();
        running = false;
      }
    });
  }

  /* ---------------------------------------------------------------------
     3D tilt and parallax.

     Driven by one rAF-throttled scroll handler rather than a listener per
     effect: a dozen handlers each doing their own getBoundingClientRect is how
     a marketing page ends up janky on a mid-range phone.

     Where the browser supports scroll-driven animations the CSS does this
     natively and this code stays out of the way — see the `@supports` block in
     the stylesheet.
     --------------------------------------------------------------------- */

  function setupParallax() {
    var layers = Array.prototype.slice.call(document.querySelectorAll("[data-parallax]"));
    var stages = Array.prototype.slice.call(document.querySelectorAll(".stage__frame"));
    if (!layers.length && !stages.length) return;

    var ticking = false;

    function frame() {
      var viewport = window.innerHeight;

      layers.forEach(function (layer) {
        var rate = parseFloat(layer.dataset.parallax) || 0.1;
        var box = layer.getBoundingClientRect();
        // Progress through the viewport, -1 (below) to 1 (above).
        var progress = (box.top + box.height / 2 - viewport / 2) / viewport;
        layer.style.setProperty("--shift", (progress * rate * 100).toFixed(2) + "px");
      });

      stages.forEach(function (stage) {
        var box = stage.getBoundingClientRect();
        // The frame starts tilted away and straightens as it reaches the
        // middle of the screen: the device rising to face you.
        var progress = Math.min(Math.max((viewport - box.top) / (viewport * 0.9), 0), 1);
        stage.style.setProperty("--tilt", ((1 - progress) * 14).toFixed(2) + "deg");
        stage.style.setProperty("--lift", ((1 - progress) * 40).toFixed(1) + "px");
        stage.style.setProperty("--dim", (0.55 + progress * 0.45).toFixed(3));
      });

      ticking = false;
    }

    function onScroll() {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(frame);
    }

    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    frame();
  }

  /* ---------------------------------------------------------------------
     Boot
     --------------------------------------------------------------------- */

  document.querySelectorAll("[data-term]").forEach(function (stage) {
    if (reduceMotion) {
      /* The same transcript, printed at once and still in colour. What this
         element is for is the output, and that survives without the typing --
         but only if the severity colours come with it. */
      var out = stage.querySelector("[data-term-out]");
      var caret = stage.querySelector("[data-caret]");
      if (caret) caret.remove();
      if (out) {
        out.textContent = "";
        TERMINAL_SCRIPT.forEach(function (step) {
          terminalLine(out, step.type, step.cls);
        });
      }
      return;
    }
    runTerminal(stage);
  });

  document.querySelectorAll("[data-demo]").forEach(function (stage) {
    if (reduceMotion) {
      // The composition stays; nothing moves. The caption keeps its opening
      // line, which is the sentence the demo exists to make.
      stage.querySelectorAll("[data-cursor]").forEach(function (c) {
        c.remove();
      });
      return;
    }
    runDemo(stage);
  });

  if (!reduceMotion) {
    // Native scroll-driven animation handles this where it exists.
    var native = CSS.supports && CSS.supports("animation-timeline: view()");
    if (!native) setupParallax();
  }
})();
