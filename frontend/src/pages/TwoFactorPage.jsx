import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router";

import { ApiError } from "../api/client";
import { safeNext, submitSecondFactor } from "../api/authActions";
import { Button } from "../components/ui/Button";
import { AuthCard, AuthField } from "../features/auth/components/AuthCard";
import { useAuthRefresh } from "../features/auth/hooks/useCurrentUser";

export function TwoFactorPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const refreshAuth = useAuthRefresh();

  const next = safeNext(params.get("next"));
  const [code, setCode] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const result = await submitSecondFactor({ code, next });
      await refreshAuth();
      navigate(result.next);
    } catch (caught) {
      const expired =
        caught instanceof ApiError && caught.code === "CHALLENGE_EXPIRED";

      if (expired) {
        // The challenge is short-lived by design. Sending them back to the
        // start is the only thing that can work, so do it rather than
        // reporting an error against a form that can no longer succeed.
        navigate(`/login?next=${encodeURIComponent(next)}`, { replace: true });
        return;
      }

      setError(
        caught instanceof ApiError ? caught.message : "That code was not accepted.",
      );
      setCode("");
      setBusy(false);
    }
  }

  return (
    <AuthCard
      error={error}
      eyebrow="One more step"
      footer={
        <span>
          Lost your device? Use one of your backup codes above, or{" "}
          <a href="/login">start again</a>.
        </span>
      }
      lede="Enter the six-digit code from your authenticator app. A backup code works here too."
      title="Two-factor"
    >
      <form className="auth-form" noValidate onSubmit={onSubmit}>
        <AuthField
          autoComplete="one-time-code"
          className="auth-field__input--code"
          id="code"
          inputMode="numeric"
          invalid={Boolean(error)}
          label="Authentication code"
          onChange={(event) => setCode(event.target.value.trim())}
          // Not capped at six: a backup code is longer, and a maxLength that
          // silently truncated one would look like the code being wrong.
          value={code}
        />
        <div className="auth-actions">
          <Button disabled={busy} type="submit">
            {busy ? "Checking…" : "Continue"}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}
