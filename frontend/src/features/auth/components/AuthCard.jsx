import { AlertTriangle } from "lucide-react";

import { InlineNotice } from "../../../components/ui/InlineNotice";

/**
 * The shell every auth screen sits in.
 *
 * Exists so five screens cannot drift into five slightly different cards, and
 * so the error region is in one place: it is announced with role="alert" and
 * placed above the fields, because a message below the submit button is one
 * that somebody who just pressed submit will not see.
 */
export function AuthCard({ children, error, eyebrow, footer, lede, title }) {
  return (
    <div className="auth-page">
      <section className="auth-card" aria-labelledby="auth-title">
        {eyebrow ? <p className="auth-card__eyebrow">{eyebrow}</p> : null}
        <h1 className="auth-card__title" id="auth-title">
          {title}
        </h1>
        {lede ? <p className="auth-card__lede">{lede}</p> : null}

        {error ? (
          <div style={{ marginBottom: "var(--wo-space-5)" }}>
            <InlineNotice icon={AlertTriangle} tone="danger">
              {error}
            </InlineNotice>
          </div>
        ) : null}

        {children}

        {footer ? <div className="auth-meta">{footer}</div> : null}
      </section>
    </div>
  );
}

/**
 * One labelled input.
 *
 * The label is a real `<label>` bound by id rather than a placeholder, because
 * a placeholder disappears the moment somebody types and leaves them with an
 * unlabelled box — and leaves a screen reader with nothing at all.
 */
export function AuthField({
  autoComplete,
  /** Extra classes, appended rather than replacing the base one. */
  className = "",
  hint,
  id,
  inputMode,
  invalid = false,
  label,
  name,
  onChange,
  required = true,
  type = "text",
  value,
  ...rest
}) {
  const hintId = hint ? `${id}-hint` : undefined;

  return (
    <div className="auth-field">
      <label className="auth-field__label" htmlFor={id}>
        {label}
      </label>
      <input
        aria-describedby={hintId}
        aria-invalid={invalid || undefined}
        autoComplete={autoComplete}
        className={`auth-field__input ${className}`.trim()}
        id={id}
        inputMode={inputMode}
        name={name ?? id}
        onChange={onChange}
        required={required}
        type={type}
        value={value}
        {...rest}
      />
      {hint ? (
        <p className="auth-field__hint" id={hintId}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/**
 * The bot trap.
 *
 * Named `website` to match what the server already checks, so both front doors
 * catch the same submissions. A real person never sees or tabs to it; a bot
 * that fills every field it finds gives itself away.
 */
export function HoneypotField({ onChange, value }) {
  return (
    <div aria-hidden="true" className="auth-honeypot">
      <label htmlFor="website">Leave this empty</label>
      <input
        autoComplete="off"
        id="website"
        name="website"
        onChange={onChange}
        tabIndex={-1}
        type="text"
        value={value}
      />
    </div>
  );
}
