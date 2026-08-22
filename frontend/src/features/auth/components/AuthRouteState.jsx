import { AlertTriangle, Clock3, LoaderCircle, LogIn, ShieldX } from "lucide-react";
import { Link } from "react-router";

import { PageTransition } from "../../../components/motion/PageTransition";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";

const COPY = {
  loading: {
    eyebrow: "Session check",
    title: "Checking your session",
    notice: "Confirming your existing Weedout session with the Python backend.",
    icon: LoaderCircle,
    tone: "neutral",
  },
  unauthenticated: {
    eyebrow: "Protected route",
    title: "Sign in to continue",
    notice: "This React route needs a Weedout session. Sign-in remains on the existing server page.",
    icon: LogIn,
    tone: "neutral",
  },
  expired: {
    eyebrow: "Session ended",
    title: "Your session expired",
    notice: "The session cookie is no longer valid. Sign in again to continue safely.",
    icon: Clock3,
    tone: "danger",
  },
  forbidden: {
    eyebrow: "403 · Protected route",
    title: "Administrator access required",
    notice: "Your session is valid, but this route is restricted to Weedout administrators.",
    icon: ShieldX,
    tone: "danger",
  },
  unavailable: {
    eyebrow: "Session check failed",
    title: "Authentication is unavailable",
    notice: "The frontend could not confirm your session. Your existing login has not been changed.",
    icon: AlertTriangle,
    tone: "danger",
  },
};

export function AuthRouteState({ loginHref, onRetry, state }) {
  const content = COPY[state];
  const Icon = content.icon;

  return (
    <PageTransition>
      <div className="auth-route-shell" data-theme="public">
        <div className="auth-route-state">
          <div className="auth-route-state__copy">
            <p className="eyebrow">{content.eyebrow}</p>
            <h1>{content.title}</h1>
            <p className="auth-route-state__lede">{content.notice}</p>
            {state === "unauthenticated" || state === "expired" ? (
              <a className="button button--primary auth-route-state__action" href={loginHref}>
                Sign in
              </a>
            ) : null}
            {state === "forbidden" ? (
              // Their dashboard, not the boundary scaffold this used to point
              // at: somebody refused from an admin URL wants the part of the
              // product they do have, not a page about routing.
              <Link className="text-link" to="/dashboard">
                Back to your dashboard
              </Link>
            ) : null}
            {state === "unavailable" ? (
              <Button className="auth-route-state__action" onClick={onRetry}>
                Try again
              </Button>
            ) : null}
          </div>
          <aside className="auth-route-state__signal" aria-label="Session status">
            <InlineNotice icon={Icon} title={content.title} tone={content.tone}>
              <p>{content.notice}</p>
            </InlineNotice>
            <div className="auth-signal-flow" aria-hidden="true">
              <span>browser cookie</span>
              <span>session check</span>
              <strong>{state}</strong>
            </div>
          </aside>
        </div>
      </div>
    </PageTransition>
  );
}
