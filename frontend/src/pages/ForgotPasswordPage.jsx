import { MailCheck } from "lucide-react";
import { useState } from "react";

import { ApiError } from "../api/client";
import { requestPasswordReset } from "../api/authActions";
import { InlineNotice } from "../components/ui/InlineNotice";
import { Button } from "../components/ui/Button";
import { AuthCard, AuthField } from "../features/auth/components/AuthCard";
import { Link } from "react-router";

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const result = await requestPasswordReset({ email });
      setSent(result.message);
    } catch (caught) {
      // Only a transport or server failure lands here. A wrong or unknown
      // address resolves successfully, because the server answers the same way
      // either way — and the screen must not add a distinction the API
      // deliberately refuses to make.
      setError(
        caught instanceof ApiError
          ? caught.message
          : "Could not send that just now. Try again shortly.",
      );
      setBusy(false);
    }
  }

  if (sent) {
    return (
      <AuthCard
        eyebrow="Check your inbox"
        footer={
          <span>
            Remembered it? <Link to="/login">Sign in</Link>
          </span>
        }
        title="On its way"
      >
        <InlineNotice icon={MailCheck} tone="success">
          {sent}
        </InlineNotice>
        <p className="auth-field__hint" style={{ marginTop: "var(--wo-space-4)" }}>
          The link is good for one hour. If it does not arrive, check your spam
          folder before asking for another.
        </p>
      </AuthCard>
    );
  }

  return (
    <AuthCard
      error={error}
      eyebrow="Account recovery"
      footer={
        <span>
          Remembered it? <Link to="/login">Sign in</Link>
        </span>
      }
      lede="Give us the address on the account and we will send a link to set a new password."
      title="Reset your password"
    >
      <form className="auth-form" noValidate onSubmit={onSubmit}>
        <AuthField
          autoComplete="username"
          id="email"
          inputMode="email"
          label="Email"
          onChange={(event) => setEmail(event.target.value)}
          type="email"
          value={email}
        />
        <div className="auth-actions">
          <Button disabled={busy} type="submit">
            {busy ? "Sending…" : "Send the link"}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}
