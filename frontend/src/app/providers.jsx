import { useSyncExternalStore } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { MotionConfig } from "motion/react";
import { Toaster } from "sonner";

import { AppErrorBoundary } from "../components/feedback/AppErrorBoundary";
import { queryClient } from "./queryClient";

function subscribeTheme(callback) {
  const observer = new MutationObserver(callback);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  return () => observer.disconnect();
}
function resolvedPalette() { return document.documentElement.dataset.theme === "dark" ? "dark" : "light"; }
function ThemeToaster() {
  const theme = useSyncExternalStore(subscribeTheme, resolvedPalette, () => "light");
  return <Toaster closeButton position="bottom-right" theme={theme} toastOptions={{ duration: 4_000 }} />;
}

export const REDUCED_MOTION_POLICY = "user";

export function AppProviders({ children, client = queryClient }) {
  return (
    <AppErrorBoundary>
      <QueryClientProvider client={client}>
        <MotionConfig reducedMotion={REDUCED_MOTION_POLICY}>
          {children}
          <ThemeToaster />
        </MotionConfig>
      </QueryClientProvider>
    </AppErrorBoundary>
  );
}
