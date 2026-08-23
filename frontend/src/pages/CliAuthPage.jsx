import { Check, Laptop, X } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router";

import { approveCliAuth, denyCliAuth, getCliAuthRequest } from "../api/cliAuth";
import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { Button } from "../components/ui/Button";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useMutation, useQuery } from "@tanstack/react-query";

/**
 * Approving a machine that asked to sign in.
 *
 * The page has one job beyond the two buttons, and it is the job the whole
 * flow depends on: give somebody enough to tell their own terminal from a
 * request they did not make. So the code is shown large and unmistakable — it
 * is what they compare — and the device label and address are shown next to a
 * plain statement that we did not verify either of them.
 *
 * The alternative, a page that just says "Approve?", trains people to click
 * yes. That is the failure this design exists to avoid, and a confirmation
 * nobody reads is worth less than no confirmation at all, because it looks
 * like a control.
 */

export function CliAuthPage() {
  const [params, setParams] = useSearchParams();
  const codeFromUrl = params.get("code") ?? "";
  const [typed, setTyped] = useState(codeFromUrl);

  if (!codeFromUrl) {
    return (
      <CodeEntry
        onSubmit={(code) => setParams({ code }, { replace: true })}
        setTyped={setTyped}
        typed={typed}
      />
    );
  }

  return <Confirm code={codeFromUrl} />;
}

function CodeEntry({ typed, setTyped, onSubmit }) {
  return (
    <div className="page-narrow cli-auth">
      <header className="page-head">
        <p className="section-label">Sign in a machine</p>
        <h1>Enter the code</h1>
      </header>
      <p className="settings-section__lede">
        Your terminal is showing an eight-character code. Type it here.
      </p>
      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (typed.trim()) onSubmit(typed.trim());
        }}
      >
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="cli-code">
            Code
          </label>
          <input
            autoComplete="off"
            className="auth-field__input cli-auth__code-input"
            id="cli-code"
            onChange={(event) => setTyped(event.target.value)}
            placeholder="HXKR-2FQP"
            spellCheck={false}
            type="text"
            value={typed}
          />
        </div>
        <div className="auth-actions">
          <Button disabled={!typed.trim()} type="submit">
            Continue
          </Button>
        </div>
      </form>
    </div>
  );
}

function Confirm({ code }) {
  const [outcome, setOutcome] = useState(null);

  const query = useQuery({
    queryKey: ["cli-auth", code],
    queryFn: ({ signal }) => getCliAuthRequest(code, { signal }),
    retry: false,
    // A pending request expires in ten minutes. Re-reading it would only be
    // useful to move the page to an expired state on its own, and doing that
    // under somebody about to click Approve is worse than letting the click
    // fail with a message.
    staleTime: Infinity,
  });

  const approve = useMutation({
    mutationFn: () => approveCliAuth(code),
    onSuccess: () => setOutcome("approved"),
  });
  const refuse = useMutation({
    mutationFn: () => denyCliAuth(code),
    onSuccess: () => setOutcome("denied"),
  });

  if (query.isPending) {
    return (
      <div className="page-narrow cli-auth">
        <AsyncLoading>Checking that code…</AsyncLoading>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="page-narrow cli-auth">
        <header className="page-head">
          <h1>That code isn&rsquo;t waiting</h1>
        </header>
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      </div>
    );
  }

  if (outcome === "approved") {
    return (
      <div className="page-narrow cli-auth">
        <header className="page-head">
          <h1>Signed in</h1>
        </header>
        <InlineNotice tone="success">
          Your terminal has the credential. You can close this tab.
        </InlineNotice>
        <p className="settings-section__lede">
          It is listed under <strong>Rule profiles and machines</strong> in your account
          settings, where you can take it back at any time.
        </p>
      </div>
    );
  }

  if (outcome === "denied") {
    return (
      <div className="page-narrow cli-auth">
        <header className="page-head">
          <h1>Refused</h1>
        </header>
        <InlineNotice tone="neutral">
          Nothing was granted, and the terminal has stopped waiting.
        </InlineNotice>
        <p className="settings-section__lede">
          If that request was not yours, nothing further is needed — no credential was
          created. Someone would have had to be reading your screen to have the code.
        </p>
      </div>
    );
  }

  const request = query.data.data;
  const failure = approve.error || refuse.error;

  return (
    <div className="page-narrow cli-auth">
      <header className="page-head">
        <p className="section-label">Sign in a machine</p>
        <h1>Is this you?</h1>
      </header>

      {failure ? <InlineNotice tone="danger">{failure.message}</InlineNotice> : null}

      <p className="settings-section__lede">
        A copy of the Weedout CLI is asking for a credential for this account. Approve it
        only if this code matches the one your terminal is showing.
      </p>

      <p className="cli-auth__code">{request.code}</p>

      <dl className="cli-auth__facts">
        <div>
          <dt>
            <Laptop aria-hidden="true" size={15} /> Called itself
          </dt>
          <dd>{request.device_label || "nothing in particular"}</dd>
        </div>
        <div>
          <dt>Came from</dt>
          <dd>{request.ip_address || "an address we could not determine"}</dd>
        </div>
      </dl>

      <p className="auth-field__hint">
        Both of those come from the machine making the request, so neither is proof of
        anything. The code is what you should be checking.
      </p>

      <div className="auth-actions cli-auth__actions">
        <Button
          disabled={approve.isPending || refuse.isPending}
          onClick={() => approve.mutate()}
          type="button"
        >
          <Check aria-hidden="true" size={16} />
          {approve.isPending ? "Approving…" : "Yes, sign it in"}
        </Button>
        <Button
          disabled={approve.isPending || refuse.isPending}
          onClick={() => refuse.mutate()}
          type="button"
          variant="secondary"
        >
          <X aria-hidden="true" size={16} />
          Not me
        </Button>
      </div>

      <p className="auth-field__hint">
        Approving grants this machine the ability to create projects and issue keys for
        them. It cannot read your findings or push a scan — those need a project key,
        which it will ask for separately.
      </p>
    </div>
  );
}
