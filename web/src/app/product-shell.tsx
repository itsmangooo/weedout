"use client";

import dynamic from "next/dynamic";

const AppRuntime = dynamic(() => import("@/ui/app/AppRuntime"), {
  ssr: false,
  loading: () => <main className="route-hydrate-fallback" aria-live="polite"><p>Loading Weedout…</p></main>,
});

export function ProductShell() { return <AppRuntime />; }
