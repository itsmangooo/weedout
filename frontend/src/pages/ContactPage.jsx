import { MailCheck } from "lucide-react";
import { useState } from "react";

import { ApiError } from "../api/client";
import { sendContactMessage } from "../api/marketing";
import { Button } from "../components/ui/Button";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useCurrentUser } from "../features/auth/hooks/useCurrentUser";

const CATEGORIES = [
  { value: "question", label: "A question" },
  { value: "bug", label: "Something is broken" },
  { value: "false_positive", label: "A finding that should not be a finding" },
  { value: "missed", label: "Something you should have caught" },
  { value: "billing", label: "Billing" },
  { value: "other", label: "Something else" },
];

export function ContactPage() {
  const { data: auth } = useCurrentUser();
  const signedIn = auth?.authenticated === true;

  const [category, setCategory] = useState("question");
  const [message, setMessage] = useState("");
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const result = await sendContactMessage({ message, category, email });
      setSent(result.message);
    } catch (caught) {
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
      <div className="page-narrow">
        <header className="page-head">
          <p className="section-label">Contact</p>
          <h1>Sent</h1>
        </header>
        <InlineNotice icon={MailCheck} tone="success">
          {sent}
        </InlineNotice>
      </div>
    );
  }

  return (
    <div className="page-narrow">
      <header className="page-head">
        <p className="section-label">Contact</p>
        <h1>Tell us what happened.</h1>
        <p className="page-head__lede">
          Especially if we reported something that was not worth reporting, or missed
          something that was. Those two are the product working badly, and we would
          rather hear about them than not.
        </p>
      </header>

      {error ? (
        <div className="u-mb-5">
          <InlineNotice tone="danger">{error}</InlineNotice>
        </div>
      ) : null}

      <form className="stack-form" noValidate onSubmit={onSubmit}>
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="category">
            What is this about?
          </label>
          <select
            className="auth-field__input"
            id="category"
            onChange={(event) => setCategory(event.target.value)}
            value={category}
          >
            {CATEGORIES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        {signedIn ? null : (
          <div className="auth-field">
            <label className="auth-field__label" htmlFor="contact-email">
              Your email
            </label>
            <input
              className="auth-field__input"
              id="contact-email"
              inputMode="email"
              onChange={(event) => setEmail(event.target.value)}
              type="email"
              value={email}
            />
            <p className="auth-field__hint">So we can reply. Nothing else is done with it.</p>
          </div>
        )}

        <div className="auth-field">
          <label className="auth-field__label" htmlFor="message">
            Message
          </label>
          <textarea
            className="auth-field__input auth-field__input--area"
            id="message"
            onChange={(event) => setMessage(event.target.value)}
            rows={10}
            value={message}
          />
          {/* Asking for specifics because a report naming the advisory and the
              package is one somebody can act on, and "it flagged something
              wrong" is not. */}
          <p className="auth-field__hint">
            If it is about a finding, the advisory id and the package name make it
            something we can actually chase.
          </p>
        </div>

        <div className="auth-actions">
          <Button disabled={busy || !message.trim()} type="submit">
            {busy ? "Sending…" : "Send"}
          </Button>
        </div>
      </form>
    </div>
  );
}
