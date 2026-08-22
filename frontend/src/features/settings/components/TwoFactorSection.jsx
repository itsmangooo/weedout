import { ShieldCheck, ShieldOff } from "lucide-react";
import { useState } from "react";

import {
  confirmTwoFactor,
  disableTwoFactor,
  regenerateBackupCodes,
  startTwoFactor,
} from "../../../api/settings";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { useSettingsMutation } from "../hooks/useSettings";

/**
 * The second factor.
 *
 * Three things here are shown exactly once and never again: the TOTP secret,
 * its QR code, and the backup codes. They are held in component state for the
 * length of the setup and deliberately not written anywhere that outlives it —
 * the server keeps only hashes and cannot re-issue them.
 *
 * Setup is two steps because a mis-scanned QR must not lock somebody out of
 * their own account. The secret stays unconfirmed until a code proves the
 * authenticator actually holds it.
 */
export function TwoFactorSection({ account }) {
  const [offer, setOffer] = useState(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState(null);
  const [password, setPassword] = useState("");

  const start = useSettingsMutation(startTwoFactor, { onSuccess: setOffer });
  const confirm = useSettingsMutation(() => confirmTwoFactor(code), {
    onSuccess: (data) => {
      setOffer(null);
      setCode("");
      setCodes(data?.backup_codes ?? null);
    },
  });
  const regenerate = useSettingsMutation(regenerateBackupCodes, {
    onSuccess: (data) => setCodes(data?.backup_codes ?? null),
  });
  const disable = useSettingsMutation(() => disableTwoFactor(password), {
    onSuccess: () => {
      setPassword("");
      setCodes(null);
    },
  });

  const failure = start.error || confirm.error || regenerate.error || disable.error;

  return (
    <section aria-labelledby="tfa-title" className="settings-section">
      <h2 id="tfa-title">
        <ShieldCheck aria-hidden="true" size={17} /> Two-factor authentication
      </h2>

      {failure ? <InlineNotice tone="danger">{failure.message}</InlineNotice> : null}

      {codes ? <BackupCodes codes={codes} onDismiss={() => setCodes(null)} /> : null}

      {account.two_factor_enabled ? (
        <>
          <p className="settings-section__lede">
            On. You will be asked for a code from your authenticator after your password.
            {account.backup_codes_total > 0 ? (
              <>
                {" "}
                {account.backup_codes_unused} of {account.backup_codes_total} backup codes
                are unused.
              </>
            ) : null}
          </p>

          <div className="settings-actions">
            <Button
              disabled={regenerate.isPending}
              onClick={() => regenerate.mutate()}
              variant="secondary"
            >
              {regenerate.isPending ? "Generating…" : "New backup codes"}
            </Button>
          </div>

          <form
            className="stack-form u-mt-5"
            onSubmit={(event) => {
              event.preventDefault();
              disable.mutate();
            }}
          >
            <div className="auth-field">
              <label className="auth-field__label" htmlFor="disable-password">
                Turn it off
              </label>
              <input
                autoComplete="current-password"
                className="auth-field__input"
                id="disable-password"
                onChange={(event) => setPassword(event.target.value)}
                type="password"
                value={password}
              />
              {/* Re-authenticated on purpose: a session left open on a shared
                  machine must not be enough to strip the control that protects
                  the account when a password leaks. */}
              <p className="auth-field__hint">
                Your password is required. A borrowed session should not be enough to
                remove your second factor.
              </p>
            </div>
            <div className="auth-actions">
              <Button disabled={disable.isPending || !password} type="submit" variant="secondary">
                <ShieldOff aria-hidden="true" size={15} />
                {disable.isPending ? "Turning off…" : "Turn off two-factor"}
              </Button>
            </div>
          </form>
        </>
      ) : offer ? (
        <>
          <p className="settings-section__lede">
            Scan this with your authenticator, then enter the code it shows.
          </p>

          <div className="tfa-setup">
            {/* The QR is an SVG string built on the server from the same URI
                shown below it. Rendered rather than linked so the secret never
                becomes an image request in anybody's logs. */}
            <div
              aria-label="Two-factor setup QR code"
              className="tfa-setup__qr"
              dangerouslySetInnerHTML={{ __html: offer.qr_svg }}
              role="img"
            />
            <div className="tfa-setup__manual">
              <p>Cannot scan it? Enter this key by hand:</p>
              <code className="selectable">{offer.secret}</code>
            </div>
          </div>

          <form
            className="stack-form"
            onSubmit={(event) => {
              event.preventDefault();
              confirm.mutate();
            }}
          >
            <div className="auth-field">
              <label className="auth-field__label" htmlFor="tfa-code">
                Code from the app
              </label>
              <input
                autoComplete="one-time-code"
                className="auth-field__input auth-field__input--code"
                id="tfa-code"
                inputMode="numeric"
                onChange={(event) => setCode(event.target.value.trim())}
                value={code}
              />
            </div>
            <div className="auth-actions">
              <Button disabled={confirm.isPending || !code} type="submit">
                {confirm.isPending ? "Checking…" : "Turn it on"}
              </Button>
            </div>
          </form>
        </>
      ) : (
        <>
          <p className="settings-section__lede">
            Off. Adding one means a stolen password is not enough to reach your account.
          </p>
          <div className="settings-actions">
            <Button disabled={start.isPending} onClick={() => start.mutate()}>
              {start.isPending ? "Preparing…" : "Set up two-factor"}
            </Button>
          </div>
        </>
      )}
    </section>
  );
}

function BackupCodes({ codes, onDismiss }) {
  return (
    <InlineNotice tone="success" title="Save these now">
      <ul className="backup-codes">
        {codes.map((code) => (
          <li className="mono selectable" key={code}>
            {code}
          </li>
        ))}
      </ul>
      <p>
        Each one works once, and this is the only time they are shown — only hashes are
        stored. They are how you get back in if you lose the authenticator.
      </p>
      <Button onClick={onDismiss} variant="secondary">
        I have saved them
      </Button>
    </InlineNotice>
  );
}
