import { SealCheck as BadgeCheck } from "@phosphor-icons/react/SealCheck";

import { PageTransition } from "../components/motion/PageTransition";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useCurrentUser } from "../features/auth/hooks/useCurrentUser";

export function AdminBoundaryPage() {
  const { data } = useCurrentUser();

  return (
    <PageTransition>
      <div className="auth-boundary-page boundary-record">
        <p className="eyebrow">Operations / access</p>
        <h1>Admin boundary confirmed.</h1>
        <InlineNotice icon={BadgeCheck} title="Administrator session" tone="success">
          <p>{data.user.email} may enter the Weedout operations console.</p>
        </InlineNotice>
        <p className="auth-boundary-page__note">
          Administrative data and actions still require server-side authorization on every request.
        </p>
      </div>
    </PageTransition>
  );
}
