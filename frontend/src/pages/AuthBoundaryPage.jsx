import { KeyRound, ShieldCheck } from "lucide-react";
import { Link } from "react-router";

import { PageTransition } from "../components/motion/PageTransition";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useCurrentUser } from "../features/auth/hooks/useCurrentUser";

export function AuthBoundaryPage() {
  const { data } = useCurrentUser();
  const user = data.user;

  return (
    <PageTransition>
      <div className="auth-boundary-page mx-auto w-full max-w-4xl px-6 py-16 sm:px-10 sm:py-20">
        <p className="eyebrow">Phase 2 · Protected route</p>
        <h1>Session boundary confirmed.</h1>
        <p className="auth-boundary-page__lede">
          React knows only the safe identity fields returned by Weedout&apos;s existing server-side
          session. Passwords, keys, billing identifiers, and authorization decisions remain in
          Python.
        </p>

        <InlineNotice icon={ShieldCheck} title="Authenticated" tone="success">
          <p>
            Signed in as <strong>{user.email}</strong> on the <strong>{user.tier}</strong> tier.
          </p>
        </InlineNotice>

        <div className="auth-boundary-page__actions">
          <Link className="text-link" to="/auth-boundary/admin">
            <KeyRound aria-hidden="true" size={16} /> Check the admin boundary
          </Link>
        </div>
      </div>
    </PageTransition>
  );
}
