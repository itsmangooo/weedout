"use client";

import { useEffect, useState } from "react";
import { RouterProvider } from "react-router";
import * as Swetrix from "swetrix";

import { initializeAppearance } from "../features/appearance/useAppearance";
import { AppProviders } from "./providers";
import { createAppRouter } from "./router";

export default function AppRuntime() {
  const [router, setRouter] = useState(null);
  useEffect(() => {
    initializeAppearance();
    setRouter(createAppRouter());
    if (process.env.NODE_ENV === "production") {
      Swetrix.init("F0r8kzzmxyo1", { apiURL: "https://analytics-api.weedout.dev/log" });
      Swetrix.trackViews();
    }
  }, []);
  if (!router) return <main className="route-hydrate-fallback" aria-live="polite"><p>Loading Weedout…</p></main>;
  return <AppProviders><RouterProvider router={router} /></AppProviders>;
}
