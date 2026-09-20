import { PageFrame } from "../../components/ui/PageFrame";
import { useState } from "react";

import { previewCampaign, sendCampaign } from "../../api/admin";
import { AsyncError, AsyncLoading } from "../../components/feedback/AsyncState";
import { Button } from "../../components/ui/Button";
import { InlineNotice } from "../../components/ui/InlineNotice";
import { useAdminMutation, useComposer } from "../../features/admin/hooks/useAdmin";
import { relativeTime } from "../../lib/time";

const EMPTY = { subject: "", body: "", audience: "one", audience_email: "" };

/**
 * Compose and send.
 *
 * The guardrail is the whole feature. Composing an email is a textarea;
 * sending one to every account is irreversible, and the failure mode is not a
 * bug report, it is six hundred people receiving something meant for one.
 *
 * So the send is two steps. The preview resolves the audience and returns an
 * exact count; the send carries that count back and the server refuses it if
 * the audience has moved. Editing the draft clears the preview, because a
 * confirmation showing a count for text nobody can see any more is not a
 * confirmation.
 */
export function AdminComposePage() {
  const query = useComposer();
  const [draft, setDraft] = useState(EMPTY);
  const [preview, setPreview] = useState(null);
  const [report, setReport] = useState(null);

  const previewing = useAdminMutation(() => previewCampaign(draft), {
    onSuccess: (result) => setPreview(result),
  });

  const sending = useAdminMutation(() => sendCampaign(draft, { confirmedCount: preview.count }), {
    onSuccess: (result) => {
      setReport(result);
      setPreview(null);
      setDraft(EMPTY);
    },
    onError: (error) => {
      // The audience moved. Clear the confirmation rather than leaving a
      // button offering a count the page has just been told is wrong — the
      // only honest way forward is to count again, so that is the only
      // button left.
      if (error?.code === "AUDIENCE_CHANGED") {
        setPreview(null);
      }
    },
  });

  function edit(name, value) {
    setDraft((current) => ({ ...current, [name]: value }));
    // Any edit invalidates the count that was agreed to.
    setPreview(null);
    setReport(null);
  }

  if (query.isPending) return <AsyncLoading>Loading the composer…</AsyncLoading>;
  if (query.isError) return <AsyncError error={query.error} onRetry={() => query.refetch()} />;

  const { variables, confirm_threshold: threshold, audiences, sends } = query.data;
  const failure = previewing.error || sending.error;

  return (
    <PageFrame className="operations-page operations-compose" eyebrow="Weedout / Operations" title={<> Compose </>} description="Write, resolve the audience, then confirm the send.">

      <div className="detail-grid">
        <div>
          {report ? <SendReport report={report} /> : null}
          {failure ? (
            <div className="u-mb-4">
              <InlineNotice tone="danger" title="Nothing was sent">
                {failure.message}
              </InlineNotice>
            </div>
          ) : null}


          <div className={`card${preview ? " u-mt-4" : ""}`}>
            <h2 className="panel__title">{preview ? "Edit the message" : "Compose"}</h2>

            <form
              onSubmit={(event) => {
                event.preventDefault();
                previewing.mutate();
              }}
            >
              <div className="field">
                <label htmlFor="audience">Who gets this</label>
                <select
                  className="select"
                  id="audience"
                  onChange={(event) => edit("audience", event.target.value)}
                  value={draft.audience}
                >
                  {audiences.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
                <p className="field__hint">Suspended accounts are never included.</p>
              </div>

              <div className="field">
                <label htmlFor="audience_email">
                  Address <em className="dim">(for “One address”)</em>
                </label>
                <input
                  className="input"
                  id="audience_email"
                  onChange={(event) => edit("audience_email", event.target.value)}
                  placeholder="someone@example.com"
                  type="email"
                  value={draft.audience_email}
                />
              </div>

              <div className="field">
                <label htmlFor="subject">Subject</label>
                <input
                  className="input"
                  id="subject"
                  maxLength={300}
                  onChange={(event) => edit("subject", event.target.value)}
                  required
                  type="text"
                  value={draft.subject}
                />
              </div>

              <div className="field">
                <label htmlFor="body">Body</label>
                <textarea
                  className="textarea textarea--prose"
                  id="body"
                  onChange={(event) => edit("body", event.target.value)}
                  placeholder="Plain text. It is sent as typed."
                  required
                  rows={14}
                  value={draft.body}
                />
                <p className="field__hint">
                  Sent as plain text, so what you type is what arrives.
                </p>
              </div>

              <div className="field">
                <span className="label">Variables</span>
                <dl className="datalist datalist--tight">
                  {Object.entries(variables).map(([name, description]) => (
                    <div key={name}>
                      <dt className="mono">{name}</dt>
                      <dd>{description}</dd>
                    </div>
                  ))}
                </dl>
              </div>

              <div className="btn-row">
                <Button disabled={previewing.isPending} type="submit">
                  {previewing.isPending ? "Counting…" : "Preview and count recipients"}
                </Button>
              </div>
            </form>
          </div>
        </div>

        <aside>          {preview ? (
            <Confirmation
              draft={draft}
              onCancel={() => setPreview(null)}
              onSend={() => sending.mutate()}
              preview={preview}
              sending={sending.isPending}
              threshold={threshold}
            />
          ) : null}

          <SendLog sends={sends} />
        </aside>
      </div>
    </PageFrame>
  );
}

/**
 * Deliberately not a modal: the count, the rendered message and the send
 * button belong on one page you can read top to bottom before committing to
 * something irreversible.
 */
function Confirmation({ draft, onCancel, onSend, preview, sending, threshold }) {
  const many = preview.count > threshold;
  const usesProjectName = draft.body.includes("project_name");

  return (
    <div className={`card${many ? " card--danger" : ""}`}>
      <h2 className="panel__title">
        {preview.count === 1
          ? "This will send to 1 person"
          : `This will send to ${preview.count} people`}
      </h2>

      <p className="field__hint u-mt-0">
        {preview.audience_label}
        {preview.audience === "one" ? "" : ", excluding suspended accounts"}.
        {many ? " There is no undo and no recall." : ""}
      </p>

      {usesProjectName && preview.without_projects ? (
        <InlineNotice tone="neutral">
          {preview.without_projects} of them {preview.without_projects === 1 ? "has" : "have"} no
          project yet, so <code>{"{{project_name}}"}</code> becomes “your project” for{" "}
          {preview.without_projects > 1 ? "them" : "that one"}.
        </InlineNotice>
      ) : null}

      <div className="mail-preview">
        <p className="mail-preview__label">As {preview.sample_email} will see it</p>
        <p className="mail-preview__subject">{preview.subject}</p>
        <pre className="mail-preview__body">{preview.body}</pre>
      </div>

      <div className="btn-row">
        {/* The count in the label is the number carried back to the server,
            so the button says exactly what it is about to do. */}
        <Button disabled={sending} onClick={onSend} variant="danger">
          {sending
            ? "Sending…"
            : `Send to ${preview.count} ${preview.count === 1 ? "person" : "people"}`}
        </Button>
        <Button onClick={onCancel} variant="secondary">
          Cancel
        </Button>
      </div>
    </div>
  );
}

function SendReport({ report }) {
  const tone = report.failed ? "danger" : "success";

  return (
    <div className="u-mb-4">
      <InlineNotice title={report.failed ? "Partly sent" : "Sent"} tone={tone}>
        <p>
          Sent to {report.sent} of {report.attempted}.
        </p>
        {report.failed ? <p>{report.errors.join("; ")}</p> : null}
      </InlineNotice>
    </div>
  );
}

function SendLog({ sends }) {
  return (
    <div className="card">
      <h2 className="panel__title">Recent sends</h2>
      {sends.length ? (
        // Every message, manual and automatic. One log, so "why did they get
        // four emails" is answerable without joining two of them.
        <ul className="sendlog">
          {sends.map((entry) => (
            <li className="sendlog__item" key={entry.id}>
              <span className={`sendlog__status sendlog__status--${entry.status}`}>
                {entry.status_label}
              </span>
              <span className="sendlog__subject">{entry.subject}</span>
              <span className="sendlog__meta">
                {entry.recipient} · {relativeTime(entry.created_at)} ·{" "}
                {entry.trigger === "admin_manual" ? `by ${entry.actor_email}` : "automatic"}
              </span>
              {entry.error ? <span className="sendlog__error">{entry.error}</span> : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className="field__hint">Nothing has gone out yet.</p>
      )}
    </div>
  );
}
