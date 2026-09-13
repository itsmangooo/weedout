import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";

import { AppProviders } from "./app/providers";
import { createAppRouter } from "./app/router";
import { initializeAppearance } from "./features/appearance/useAppearance";
import "./styles/globals.css";

initializeAppearance();
const router = createAppRouter();

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <AppProviders>
      <RouterProvider router={router} />
    </AppProviders>
  </StrictMode>,
);
