import { useEffect, useId, useRef, useState } from "react";
import { useLocation } from "react-router";

export function useNavigationDisclosure() {
  const { key } = useLocation();
  const id = useId();
  const trigger = useRef(null);
  const [openedAt, setOpenedAt] = useState(null);
  const open = openedAt === key;
  useEffect(() => {
    if (!open) return;
    function close(event) {
      if (event.key !== "Escape") return;
      setOpenedAt(null);
      trigger.current?.focus();
    }
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [open]);
  return { id, trigger, open, toggle: () => setOpenedAt(open ? null : key), close: () => setOpenedAt(null) };
}
