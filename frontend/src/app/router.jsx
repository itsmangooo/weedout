import { createBrowserRouter, createMemoryRouter } from "react-router";

import { RouteErrorBoundary } from "../components/feedback/AppErrorBoundary";
import { AdminShell } from "../components/layout/AdminShell";
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
            path: "pricing",
            lazy: async () => {
              const { PricingPage } = await import("../pages/PricingPage");
              return { Component: PricingPage };
            },
          },
          {
            path: "cli",
            lazy: async () => {
              const { CliPage } = await import("../pages/CliPage");
              return { Component: CliPage };
            },
          },
          {
            path: "contact",
            lazy: async () => {
              const { ContactPage } = await import("../pages/ContactPage");
              return { Component: ContactPage };
            },
          },
          {
            path: "docs",
            lazy: async () => {
              const { DocsIndexPage } = await import("../pages/DocsPage");
              return { Component: DocsIndexPage };
            },
          },
          {
            path: "docs/:slug",
            lazy: async () => {
              const { DocsArticlePage } = await import("../pages/DocsPage");
              return { Component: DocsArticlePage };
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
                path: "billing",
                lazy: async () => {
                  const { BillingPage } = await import("../pages/BillingPage");
                  return { Component: BillingPage };
                },
              },
              {
                path: "billing/success",
                lazy: async () => {
                  const { BillingPage } = await import("../pages/BillingPage");
                  return { Component: BillingPage };
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
          {
            // The admin panel. Nested inside ProtectedRoute so an expired
            // session shows "sign in" rather than "not allowed", then behind
            // AdminRoute, which is presentation only — every endpoint under
            // /api/internal/admin enforces the same rule in Python.
            element: <AdminRoute />,
            children: [
              {
                element: <AdminShell />,
                children: [
                  {
                    path: "admin",
                    lazy: async () => {
                      const { AdminOverviewPage } = await import(
                        "../pages/admin/AdminOverviewPage"
                      );
                      return { Component: AdminOverviewPage };
                    },
                  },
                  {
                    path: "admin/users",
                    lazy: async () => {
                      const { AdminUsersPage } = await import("../pages/admin/AdminUsersPage");
                      return { Component: AdminUsersPage };
                    },
                  },
                  {
                    path: "admin/users/:userId",
                    lazy: async () => {
                      const { AdminUserPage } = await import("../pages/admin/AdminUserPage");
                      return { Component: AdminUserPage };
                    },
                  },
                  {
                    path: "admin/billing",
                    lazy: async () => {
                      const { AdminBillingPage } = await import(
                        "../pages/admin/AdminBillingPage"
                      );
                      return { Component: AdminBillingPage };
                    },
                  },
                  {
                    path: "admin/inbox",
                    lazy: async () => {
                      const { AdminInboxPage } = await import("../pages/admin/AdminInboxPage");
                      return { Component: AdminInboxPage };
                    },
                  },
                  {
                    path: "admin/inbox/:messageId",
                    lazy: async () => {
                      const { AdminMessagePage } = await import(
                        "../pages/admin/AdminMessagePage"
                      );
                      return { Component: AdminMessagePage };
                    },
                  },
                  {
                    path: "admin/email",
                    lazy: async () => {
                      const { AdminComposePage } = await import(
                        "../pages/admin/AdminComposePage"
                      );
                      return { Component: AdminComposePage };
                    },
                  },
                  {
                    path: "admin/docs",
                    lazy: async () => {
                      const { AdminDocsPage } = await import("../pages/admin/AdminDocsPage");
                      return { Component: AdminDocsPage };
                    },
                  },
                  {
                    // Before ":pageId", so "new" is the create form rather
                    // than a lookup for a page whose id is the word "new".
                    path: "admin/docs/new",
                    lazy: async () => {
                      const { AdminDocEditPage } = await import(
                        "../pages/admin/AdminDocEditPage"
                      );
                      return { Component: AdminDocEditPage };
                    },
                  },
                  {
                    path: "admin/docs/:pageId",
                    lazy: async () => {
                      const { AdminDocEditPage } = await import(
                        "../pages/admin/AdminDocEditPage"
                      );
                      return { Component: AdminDocEditPage };
                    },
                  },
                  {
                    path: "admin/audit",
                    lazy: async () => {
                      const { AdminAuditPage } = await import("../pages/admin/AdminAuditPage");
                      return { Component: AdminAuditPage };
                    },
                  },
                ],
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
