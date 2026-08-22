import { createBrowserRouter, createMemoryRouter } from "react-router";

import { RouteErrorBoundary } from "../components/feedback/AppErrorBoundary";
import { AppShell } from "../components/layout/AppShell";
import { FoundationLayout } from "../components/layout/FoundationLayout";
import { AdminRoute } from "../features/auth/components/AdminRoute";
import { ProtectedRoute } from "../features/auth/components/ProtectedRoute";
import { AdminBoundaryPage } from "../pages/AdminBoundaryPage";
import { AuthBoundaryPage } from "../pages/AuthBoundaryPage";
import { NotFoundPage } from "../pages/NotFoundPage";
import { App } from "./App";

export const appRoutes = [
  {
    path: "/",
    element: <App />,
    errorElement: <RouteErrorBoundary />,
    hydrateFallbackElement: (
      <main className="route-hydrate-fallback" aria-live="polite">
        <p>Loading Weedout…</p>
      </main>
    ),
    children: [
      {
        element: <FoundationLayout />,
        children: [
          {
            index: true,
            lazy: async () => {
              const { FoundationPage } = await import("../pages/FoundationPage");
              return { Component: FoundationPage };
            },
          },
          {
            path: "login",
            lazy: async () => {
              const { LoginPage } = await import("../pages/LoginPage");
              return { Component: LoginPage };
            },
          },
          {
            path: "login/2fa",
            lazy: async () => {
              const { TwoFactorPage } = await import("../pages/TwoFactorPage");
              return { Component: TwoFactorPage };
            },
          },
          {
            path: "signup",
            lazy: async () => {
              const { SignupPage } = await import("../pages/SignupPage");
              return { Component: SignupPage };
            },
          },
          {
            path: "forgot-password",
            lazy: async () => {
              const { ForgotPasswordPage } = await import("../pages/ForgotPasswordPage");
              return { Component: ForgotPasswordPage };
            },
          },
          {
            path: "reset-password",
            lazy: async () => {
              const { ResetPasswordPage } = await import("../pages/ResetPasswordPage");
              return { Component: ResetPasswordPage };
            },
          },
          {
            element: <ProtectedRoute />,
            children: [
              {
                path: "auth-boundary",
                element: <AuthBoundaryPage />,
              },
              {
                element: <AdminRoute />,
                children: [
                  {
                    path: "auth-boundary/admin",
                    element: <AdminBoundaryPage />,
                  },
                ],
              },
            ],
          },
          {
            path: "*",
            element: <NotFoundPage />,
          },
        ],
      },
      {
        element: <ProtectedRoute />,
        children: [
          {
            element: <AppShell />,
            children: [
              {
                path: "dashboard",
                lazy: async () => {
                  const { DashboardPage } = await import("../pages/DashboardPage");
                  return { Component: DashboardPage };
                },
              },
              {
                path: "targets/new",
                lazy: async () => {
                  const { NewProjectPage } = await import("../pages/NewProjectPage");
                  return { Component: NewProjectPage };
                },
              },
              {
                path: "settings",
                lazy: async () => {
                  const { SettingsPage } = await import("../pages/SettingsPage");
                  return { Component: SettingsPage };
                },
              },
              {
                path: "alerts",
                lazy: async () => {
                  const { AlertsPage } = await import("../pages/AlertsPage");
                  return { Component: AlertsPage };
                },
              },
              {
                path: "alerts/:alertId",
                lazy: async () => {
                  const { AlertPage } = await import("../pages/AlertPage");
                  return { Component: AlertPage };
                },
              },
              {
                path: "targets/:projectId",
                lazy: async () => {
                  const { ProjectPage } = await import("../pages/ProjectPage");
                  return { Component: ProjectPage };
                },
              },
            ],
          },
        ],
      },
    ],
  },
];

export function createAppRouter({ initialEntries } = {}) {
  if (initialEntries) {
    return createMemoryRouter(appRoutes, { initialEntries });
  }

  return createBrowserRouter(appRoutes);
}
