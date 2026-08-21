import { QueryClientProvider } from "@tanstack/react-query";
import { MotionConfig } from "motion/react";
import { Toaster } from "sonner";

import { AppErrorBoundary } from "../components/feedback/AppErrorBoundary";
import { queryClient } from "./queryClient";

export const REDUCED_MOTION_POLICY = "user";

export function AppProviders({ children, client = queryClient }) {
  return (
    <AppErrorBoundary>
      <QueryClientProvider client={client}>
        <MotionConfig reducedMotion={REDUCED_MOTION_POLICY}>
          {children}
          <Toaster
            closeButton
            position="bottom-right"
            theme="dark"
            toastOptions={{ duration: 4_000 }}
          />
        </MotionConfig>
      </QueryClientProvider>
    </AppErrorBoundary>
  );
}
