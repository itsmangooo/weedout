import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router";

import { ApiError } from "../api/client";
import { safeNext, signIn } from "../api/authActions";
import { Button } from "../components/ui/Button";
import { AuthCard, AuthField } from "../features/auth/components/AuthCard";
import { useAuthRefresh } from "../features/auth/hooks/useCurrentUser";

export function LoginPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const refreshAuth = useAuthRefresh();

  const next = safeNext(params.get("next"));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const result = await signIn({ email, password, next });

      if (result.status === "two_factor_required") {
        // Not an error. The password was right and there is one more step, so
        // the screen changes rather than the message.
        navigate(`/login/2fa?next=${encodeURIComponent(result.next)}`);
        return;
      }

      // The cached identity is stale the instant a session exists. Refreshing
      // before navigating stops the dashboard's own guard bouncing the user
      // back to this page with the session they just created.
      await refreshAuth();
      navigate(result.next);
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.message
          : "Something went wrong signing in. Try again.",
      );
      setBusy(false);
    }
  }

  return (
    <AuthCard
      error={error}
      eyebrow="Welcome back"
      footer={
        <div className="auth-meta__row">
          <span>
            No account? <a href="/signup">Create one</a>
          </span>
          <a href="/forgot-password">Forgot your password?</a>
        </div>
      }
      lede="Sign in to see what actually needs your attention."
      title="Sign in"
    >
      <form className="auth-form" noValidate onSubmit={onSubmit}>
        <AuthField
          autoComplete="username"
          id="email"
          inputMode="email"
          invalid={Boolean(error)}
          label="Email"
          onChange={(event) => setEmail(event.target.value)}
          type="email"
          value={email}
        />
        <AuthField
          autoComplete="current-password"
          id="password"
          invalid={Boolean(error)}
          label="Password"
          onChange={(event) => setPassword(event.target.value)}
          type="password"
          value={password}
        />
        <div className="auth-actions">
          <Button disabled={busy} type="submit">
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}
