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
      <div className="auth-boundary-page boundary-record">
        <p className="eyebrow">Account / session</p>
        <h1>Session boundary confirmed.</h1>
        <p className="auth-boundary-page__lede">
          Your Weedout session is active. Sensitive credentials remain outside the browser view.
        </p>

        <InlineNotice icon={ShieldCheck} title="Authenticated" tone="success">
          <p>
            Signed in as <strong>{user.email}</strong> on the <strong>{user.tier}</strong> tier.
          </p>
        </InlineNotice>

        <div className="auth-boundary-page__actions">
          <Link className="text-link" to="/auth-boundary/admin">
            <KeyRound aria-hidden="true" size={16} /> Check administrator access
          </Link>
        </div>
      </div>
    </PageTransition>
  );
}
