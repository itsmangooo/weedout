import { KeyRound } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";

import { ApiError } from "../api/client";
import { resetPassword } from "../api/authActions";
import { InlineNotice } from "../components/ui/InlineNotice";
import { Button } from "../components/ui/Button";
import { AuthCard, AuthField } from "../features/auth/components/AuthCard";

const MIN_PASSWORD_LENGTH = 10;

export function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const mismatch = confirm.length > 0 && password !== confirm;

  async function onSubmit(event) {
    event.preventDefault();

    if (mismatch) {
      // Caught here as well as on the server. This is the one screen where a
      // typo locks somebody out of the account they are recovering, so the
      // check is worth making twice.
      setError("Those passwords do not match.");
      return;
    }

    setBusy(true);
    setError(null);

    try {
      const result = await resetPassword({
        token,
        password,
        passwordConfirm: confirm,
      });
      setDone(result.message);
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.message
          : "Could not change the password. Ask for a new link.",
      );
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <AuthCard
        eyebrow="Account recovery"
        footer={
          <span>
            <Link to="/forgot-password">Ask for a new link</Link>
          </span>
        }
        title="That link is incomplete"
      >
        <p className="auth-card__lede">
          The address is missing its token, which usually means the link was cut
          short by an email client. Asking for a fresh one is the quickest fix.
        </p>
      </AuthCard>
    );
  }

  if (done) {
    return (
      <AuthCard eyebrow="Done" title="Password changed">
        <InlineNotice icon={KeyRound} tone="success">
          {done}
        </InlineNotice>
        <p className="auth-field__hint" style={{ marginTop: "var(--wo-space-4)" }}>
          Every other session was signed out, so anything still holding the old
          password no longer works.
        </p>
        <div className="auth-actions" style={{ marginTop: "var(--wo-space-5)" }}>
          <Link className="button button--primary" to="/login">
            Sign in
          </Link>
        </div>
      </AuthCard>
    );
  }

  return (
    <AuthCard
      error={error}
      eyebrow="Account recovery"
      lede="Choose something you have not used here before."
      title="Set a new password"
    >
      <form className="auth-form" noValidate onSubmit={onSubmit}>
        <AuthField
          autoComplete="new-password"
          hint={`At least ${MIN_PASSWORD_LENGTH} characters.`}
          id="password"
          label="New password"
          minLength={MIN_PASSWORD_LENGTH}
          onChange={(event) => setPassword(event.target.value)}
          type="password"
          value={password}
        />
        <AuthField
          autoComplete="new-password"
          hint={mismatch ? "These do not match yet." : undefined}
          id="password_confirm"
          invalid={mismatch}
          label="Confirm new password"
          onChange={(event) => setConfirm(event.target.value)}
          type="password"
          value={confirm}
        />
        <div className="auth-actions">
          <Button disabled={busy || mismatch} type="submit">
            {busy ? "Changing…" : "Change password"}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}
