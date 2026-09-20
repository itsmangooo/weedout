import { useState } from "react";
import { Link, useNavigate } from "react-router";

import { ApiError } from "../api/client";
import { signUp } from "../api/authActions";
import { Button } from "../components/ui/Button";
import { AuthCard, AuthField, HoneypotField } from "../features/auth/components/AuthCard";
import { useAuthRefresh } from "../features/auth/hooks/useCurrentUser";

/** Matches the server's rule, so the requirement is stated before it is enforced. */
const MIN_PASSWORD_LENGTH = 10;

export function SignupPage() {
  const navigate = useNavigate();
  const refreshAuth = useAuthRefresh();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [website, setWebsite] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const result = await signUp({ email, password, website });
      await refreshAuth();
      navigate(result.next);
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.message
          : "Something went wrong creating your account. Try again.",
      );
      setBusy(false);
    }
  }

  return (
    <AuthCard
      error={error}
      eyebrow="Get started"
      footer={
        <span>
          Already have an account? <Link to="/login">Sign in</Link>
        </span>
      }
      lede="Watch one project free, and only hear from us when something is actually reachable."
      title="Create your account"
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
        <AuthField
          autoComplete="new-password"
          hint={`At least ${MIN_PASSWORD_LENGTH} characters. A passphrase beats a short complicated one.`}
          id="password"
          label="Password"
          minLength={MIN_PASSWORD_LENGTH}
          onChange={(event) => setPassword(event.target.value)}
          type="password"
          value={password}
        />
        <HoneypotField onChange={(event) => setWebsite(event.target.value)} value={website} />
        <div className="auth-actions">
          <Button disabled={busy} type="submit">
            {busy ? "Creating your account…" : "Create account"}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}
