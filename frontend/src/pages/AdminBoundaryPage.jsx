import { BadgeCheck } from "lucide-react";

import { PageTransition } from "../components/motion/PageTransition";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useCurrentUser } from "../features/auth/hooks/useCurrentUser";

export function AdminBoundaryPage() {
  const { data } = useCurrentUser();

  return (
    <PageTransition>
      <div className="auth-boundary-page mx-auto w-full max-w-4xl px-6 py-16 sm:px-10 sm:py-20">
        <p className="eyebrow">Phase 2 · Admin route</p>
        <h1>Admin boundary confirmed.</h1>
        <InlineNotice icon={BadgeCheck} title="Administrator session" tone="success">
          <p>{data.user.email} may enter this React route.</p>
        </InlineNotice>
        <p className="auth-boundary-page__note">
          This client-side guard controls presentation only. Every future admin data endpoint must
          independently enforce administrator authorization in Python.
        </p>
      </div>
    </PageTransition>
  );
}
