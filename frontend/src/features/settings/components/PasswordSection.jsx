import { Lock } from "@phosphor-icons/react/Lock";
import { useState } from "react";

import { changePassword } from "../../../api/settings";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { useSettingsMutation } from "../hooks/useSettings";

const MIN_PASSWORD_LENGTH = 10;

export function PasswordSection() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [done, setDone] = useState(false);

  const change = useSettingsMutation(
    () => changePassword({ currentPassword, newPassword }),
    {
      onSuccess: () => {
        setCurrentPassword("");
        setNewPassword("");
        setDone(true);
      },
    },
  );

  return (
    <section aria-labelledby="password-title" className="settings-section">
      <h2 id="password-title">
        <Lock aria-hidden="true" size={17} /> Password
      </h2>

      {change.isError ? <InlineNotice tone="danger">{change.error.message}</InlineNotice> : null}
      {done ? (
        <InlineNotice tone="success">
          Changed. Every other session was signed out; this one stayed.
        </InlineNotice>
      ) : null}

      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          setDone(false);
          change.mutate();
        }}
      >
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="current-password">
            Current password
          </label>
          <input
            autoComplete="current-password"
            className="auth-field__input"
            id="current-password"
            onChange={(event) => setCurrentPassword(event.target.value)}
            type="password"
            value={currentPassword}
          />
        </div>

        <div className="auth-field">
          <label className="auth-field__label" htmlFor="new-password">
            New password
          </label>
          <input
            autoComplete="new-password"
            className="auth-field__input"
            id="new-password"
            minLength={MIN_PASSWORD_LENGTH}
            onChange={(event) => setNewPassword(event.target.value)}
            type="password"
            value={newPassword}
          />
          <p className="auth-field__hint">
            At least {MIN_PASSWORD_LENGTH} characters. Changing it signs out everywhere
            else — which is the point, if the old one leaked.
          </p>
        </div>

        <div className="auth-actions">
          <Button
            disabled={change.isPending || !currentPassword || !newPassword}
            type="submit"
            variant="secondary"
          >
            {change.isPending ? "Changing…" : "Change password"}
          </Button>
        </div>
      </form>
    </section>
  );
}
