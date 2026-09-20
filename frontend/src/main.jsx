import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";
import * as Swetrix from "swetrix";

import { AppProviders } from "./app/providers";
import { createAppRouter } from "./app/router";
import { initializeAppearance } from "./features/appearance/useAppearance";
import "./styles/globals.css";

initializeAppearance();

if (import.meta.env.PROD) {
  Swetrix.init("F0r8kzzmxyo1", {
    apiURL: "https://analytics-api.weedout.dev/log",
  });

  Swetrix.trackViews();
}

const router = createAppRouter();

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <AppProviders>
      <RouterProvider router={router} />
    </AppProviders>
  </StrictMode>
);