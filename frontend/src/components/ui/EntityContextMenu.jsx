import { Children, cloneElement, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { MoreHorizontal } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";

const EDGE_GAP = 8;
const NATIVE_CONTEXT_SELECTOR = "a, button, input, textarea, select, option, code, pre";

function enabledItems(menu) {
  return Array.from(menu?.querySelectorAll('[role="menuitem"]:not([aria-disabled="true"])') || []);
}

export function EntityContextMenu({ children, items, label }) {
  const [position, setPosition] = useState(null);
  const menuRef = useRef(null);
  const returnFocusRef = useRef(null);

  const close = useCallback((restoreFocus = true) => {
    setPosition(null);
    if (restoreFocus) {
      requestAnimationFrame(() => returnFocusRef.current?.focus?.());
    }
  }, []);

  const openAt = useCallback((x, y, focusTarget) => {
    returnFocusRef.current = focusTarget || document.activeElement;
    setPosition({ x, y });
  }, []);

  const targetProps = {
    onContextMenu(event) {
      const interactive = event.target.closest?.(NATIVE_CONTEXT_SELECTOR);
      if (interactive && event.currentTarget.contains(interactive)) {
        return;
      }
      event.preventDefault();
      openAt(event.clientX, event.clientY, document.activeElement);
    },
  };

  const trigger = (
    <button
      aria-haspopup="menu"
      aria-expanded={Boolean(position)}
      aria-label={label}
      className="entity-menu-trigger"
      onClick={(event) => {
        const rect = event.currentTarget.getBoundingClientRect();
        openAt(rect.right, rect.bottom + 6, event.currentTarget);
      }}
      type="button"
    >
      <MoreHorizontal aria-hidden="true" size={17} />
    </button>
  );

  useLayoutEffect(() => {
    if (!position || !menuRef.current) {
      return;
    }

    const rect = menuRef.current.getBoundingClientRect();
    const next = {
      x: Math.max(EDGE_GAP, Math.min(position.x, window.innerWidth - rect.width - EDGE_GAP)),
      y: Math.max(EDGE_GAP, Math.min(position.y, window.innerHeight - rect.height - EDGE_GAP)),
    };
    if (next.x !== position.x || next.y !== position.y) {
      setPosition(next);
      return;
    }

    enabledItems(menuRef.current)[0]?.focus();
  }, [position]);

  useEffect(() => {
    if (!position) {
      return undefined;
    }

    const handleOutside = (event) => {
      if (!menuRef.current?.contains(event.target)) {
        close(false);
      }
    };
    const handleViewportChange = () => close(false);
    document.addEventListener("pointerdown", handleOutside);
    window.addEventListener("resize", handleViewportChange);
    window.addEventListener("scroll", handleViewportChange, true);

    return () => {
      document.removeEventListener("pointerdown", handleOutside);
      window.removeEventListener("resize", handleViewportChange);
      window.removeEventListener("scroll", handleViewportChange, true);
    };
  }, [close, position]);

  function handleKeyDown(event) {
    const entries = enabledItems(menuRef.current);
    const current = entries.indexOf(document.activeElement);
    let next;

    if (event.key === "ArrowDown") {
      next = (current + 1) % entries.length;
    } else if (event.key === "ArrowUp") {
      next = (current - 1 + entries.length) % entries.length;
    } else if (event.key === "Home") {
      next = 0;
    } else if (event.key === "End") {
      next = entries.length - 1;
    } else if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    } else if (event.key === "Tab") {
      close(false);
      return;
    } else {
      return;
    }

    event.preventDefault();
    entries[next]?.focus();
  }

  const menu = (
    <AnimatePresence>
      {position ? (
        <motion.div
          animate={{ opacity: 1, scale: 1, y: 0 }}
          aria-label={label}
          className="entity-context-menu"
          exit={{ opacity: 0, scale: 0.98, y: -2 }}
          initial={{ opacity: 0, scale: 0.98, y: -3 }}
          onKeyDown={handleKeyDown}
          ref={menuRef}
          role="menu"
          style={{ left: position.x, top: position.y }}
          transition={{ duration: 0.12, ease: [0.16, 1, 0.3, 1] }}
        >
          {items.map((item, index) => {
            if (item.type === "separator") {
              return <div className="entity-context-menu__separator" key={`separator-${index}`} role="separator" />;
            }

            const Icon = item.icon;
            const shared = {
              "aria-disabled": item.disabled || undefined,
              className: "entity-context-menu__item",
              onClick(event) {
                if (item.disabled) {
                  event.preventDefault();
                  return;
                }
                item.onSelect?.();
                close(false);
              },
              role: "menuitem",
              tabIndex: -1,
            };
            const content = (
              <>
                {Icon ? <Icon aria-hidden="true" size={15} /> : null}
                <span>{item.label}</span>
              </>
            );

            return item.href ? (
              <a href={item.href} key={item.label} {...shared}>
                {content}
              </a>
            ) : (
              <button key={item.label} type="button" {...shared}>
                {content}
              </button>
            );
          })}
        </motion.div>
      ) : null}
    </AnimatePresence>
  );

  const target = Children.only(children);
  const targetWithMenu = cloneElement(
    target,
    // The injected handler reads the saved focus target only after user input.
    // eslint-disable-next-line react-hooks/refs
    targetProps,
    ...Children.toArray(target.props.children),
    trigger,
  );

  return (
    <>
      {targetWithMenu}
      {typeof document === "undefined" ? null : createPortal(menu, document.body)}
    </>
  );
}
