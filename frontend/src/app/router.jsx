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
            handle: { title: "Weed out the noise in your CVE alerts" },
            lazy: async () => {
              const { FoundationPage } = await import("../pages/FoundationPage");
              return { Component: FoundationPage };
            },
          },
          {
            path: "pricing",
            handle: { title: "Pricing" },
            lazy: async () => {
              const { PricingPage } = await import("../pages/PricingPage");
              return { Component: PricingPage };
            },
          },
          {
            // Outside the signed-in boundary, deliberately. A status page you
            // have to sign in to read is not a status page -- the people most
            // likely to load it are the ones who cannot get in.
            path: "status",
            handle: { title: "Status" },
            lazy: async () => {
              const { StatusPage } = await import("../pages/StatusPage");
              return { Component: StatusPage };
            },
          },
          {
            path: "cli",
            handle: { title: "Command line" },
            lazy: async () => {
              const { CliPage } = await import("../pages/CliPage");
              return { Component: CliPage };
            },
          },
          {
            path: "contact",
            handle: { title: "Contact" },
            lazy: async () => {
              const { ContactPage } = await import("../pages/ContactPage");
              return { Component: ContactPage };
            },
          },
          {
            path: "docs",
            handle: { title: "Docs" },
            lazy: async () => {
              const { DocsIndexPage } = await import("../pages/DocsPage");
              return { Component: DocsIndexPage };
            },
          },
          {
            path: "docs/:slug",
            // No title here: the article sets its own from the page it loaded,
            // and "Docs" on every one of them makes a row of tabs useless.
            lazy: async () => {
              const { DocsArticlePage } = await import("../pages/DocsPage");
              return { Component: DocsArticlePage };
            },
          },
          {
            path: "login",
            handle: { title: "Sign in" },
            lazy: async () => {
              const { LoginPage } = await import("../pages/LoginPage");
              return { Component: LoginPage };
            },
          },
          {
            path: "login/2fa",
            handle: { title: "Two-factor" },
            lazy: async () => {
              const { TwoFactorPage } = await import("../pages/TwoFactorPage");
              return { Component: TwoFactorPage };
            },
          },
          {
            path: "signup",
            handle: { title: "Create an account" },
            lazy: async () => {
              const { SignupPage } = await import("../pages/SignupPage");
              return { Component: SignupPage };
            },
          },
          {
            path: "forgot-password",
            handle: { title: "Reset your password" },
            lazy: async () => {
              const { ForgotPasswordPage } = await import("../pages/ForgotPasswordPage");
              return { Component: ForgotPasswordPage };
            },
          },
          {
            path: "reset-password",
            handle: { title: "Choose a new password" },
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
            handle: { title: "Not found" },
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
                handle: { title: "Dashboard" },
                lazy: async () => {
                  const { DashboardPage } = await import("../pages/DashboardPage");
                  return { Component: DashboardPage };
                },
              },
              {
                path: "targets/new",
                handle: { title: "Add a project" },
                lazy: async () => {
                  const { NewProjectPage } = await import("../pages/NewProjectPage");
                  return { Component: NewProjectPage };
                },
              },
              {
                path: "billing",
                handle: { title: "Billing" },
                lazy: async () => {
                  const { BillingPage } = await import("../pages/BillingPage");
                  return { Component: BillingPage };
                },
              },
              {
                path: "billing/success",
                handle: { title: "Billing" },
                lazy: async () => {
                  const { BillingPage } = await import("../pages/BillingPage");
                  return { Component: BillingPage };
                },
              },
              {
                // Approving a machine that ran `weedout auth`. Inside the
                // signed-in boundary because the whole point is that a person
                // with the account grants this deliberately; a stranger
                // reaching it gets sent to sign in first, which is correct.
                path: "cli-auth",
                handle: { title: "Sign in a machine" },
                lazy: async () => {
                  const { CliAuthPage } = await import("../pages/CliAuthPage");
                  return { Component: CliAuthPage };
                },
              },
              {
                path: "settings",
                handle: { title: "Settings" },
                lazy: async () => {
                  const { SettingsPage } = await import("../pages/SettingsPage");
                  return { Component: SettingsPage };
                },
              },
              {
                path: "alerts",
                handle: { title: "Findings" },
                lazy: async () => {
                  const { AlertsPage } = await import("../pages/AlertsPage");
                  return { Component: AlertsPage };
                },
              },
              {
                path: "alerts/:alertId",
                handle: { title: "Finding" },
                lazy: async () => {
                  const { AlertPage } = await import("../pages/AlertPage");
                  return { Component: AlertPage };
                },
              },
              {
                path: "targets/:projectId",
                handle: { title: "Project" },
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
                    handle: { title: "Admin" },
                    lazy: async () => {
                      const { AdminOverviewPage } = await import(
                        "../pages/admin/AdminOverviewPage"
                      );
                      return { Component: AdminOverviewPage };
                    },
                  },
                  {
                    path: "admin/users",
                    handle: { title: "Users" },
                    lazy: async () => {
                      const { AdminUsersPage } = await import("../pages/admin/AdminUsersPage");
                      return { Component: AdminUsersPage };
                    },
                  },
                  {
                    path: "admin/users/:userId",
                    handle: { title: "User" },
                    lazy: async () => {
                      const { AdminUserPage } = await import("../pages/admin/AdminUserPage");
                      return { Component: AdminUserPage };
                    },
                  },
                  {
                    path: "admin/billing",
                    handle: { title: "Revenue" },
                    lazy: async () => {
                      const { AdminBillingPage } = await import(
                        "../pages/admin/AdminBillingPage"
                      );
                      return { Component: AdminBillingPage };
                    },
                  },
                  {
                    path: "admin/inbox",
                    handle: { title: "Inbox" },
                    lazy: async () => {
                      const { AdminInboxPage } = await import("../pages/admin/AdminInboxPage");
                      return { Component: AdminInboxPage };
                    },
                  },
                  {
                    path: "admin/inbox/:messageId",
                    handle: { title: "Message" },
                    lazy: async () => {
                      const { AdminMessagePage } = await import(
                        "../pages/admin/AdminMessagePage"
                      );
                      return { Component: AdminMessagePage };
                    },
                  },
                  {
                    path: "admin/email",
                    handle: { title: "Compose" },
                    lazy: async () => {
                      const { AdminComposePage } = await import(
                        "../pages/admin/AdminComposePage"
                      );
                      return { Component: AdminComposePage };
                    },
                  },
                  {
                    path: "admin/docs",
                    handle: { title: "Docs" },
                    lazy: async () => {
                      const { AdminDocsPage } = await import("../pages/admin/AdminDocsPage");
                      return { Component: AdminDocsPage };
                    },
                  },
                  {
                    // Before ":pageId", so "new" is the create form rather
                    // than a lookup for a page whose id is the word "new".
                    path: "admin/docs/new",
                    handle: { title: "New page" },
                    lazy: async () => {
                      const { AdminDocEditPage } = await import(
                        "../pages/admin/AdminDocEditPage"
                      );
                      return { Component: AdminDocEditPage };
                    },
                  },
                  {
                    path: "admin/docs/:pageId",
                    handle: { title: "Edit page" },
                    lazy: async () => {
                      const { AdminDocEditPage } = await import(
                        "../pages/admin/AdminDocEditPage"
                      );
                      return { Component: AdminDocEditPage };
                    },
                  },
                  {
                    path: "admin/audit",
                    handle: { title: "Audit log" },
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
