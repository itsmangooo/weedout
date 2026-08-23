import { KeyRound } from "lucide-react";
import { useState } from "react";

import { createAccountKey, revokeAccountKey } from "../../../api/settings";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { relativeTime } from "../../../lib/time";
import { useSettingsMutation } from "../hooks/useSettings";
import { Link } from "react-router";

const SCOPES = [
  { value: "scan", label: "Push scans — for CI" },
  { value: "read", label: "Read findings — for dashboards and the CLI" },
  { value: "manage", label: "Full access — including editing scan rules" },
];

export function AccountKeys({ keys, projects }) {
  const [targetId, setTargetId] = useState(projects[0]?.id ?? "");
  const [name, setName] = useState("");
  const [scope, setScope] = useState("scan");
  const [issued, setIssued] = useState(null);

  const create = useSettingsMutation(
    () => createAccountKey({ targetId: Number(targetId), name, scope }),
    { onSuccess: setIssued },
  );
  const revoke = useSettingsMutation((id) => revokeAccountKey(id));

  const failure = create.error || revoke.error;

  return (
    <section aria-labelledby="keys-title" className="settings-section">
      <h2 id="keys-title">
        <KeyRound aria-hidden="true" size={17} /> API keys
      </h2>

      {failure ? <InlineNotice tone="danger">{failure.message}</InlineNotice> : null}

      {issued ? (
        <InlineNotice tone="success" title="Copy this now">
          <p className="mono selectable">{issued.token}</p>
          <p>
            The only time it is shown — only its hash is stored. If you lose it, revoke
            the key and make another.
          </p>
        </InlineNotice>
      ) : null}

      {projects.length === 0 ? (
        <p className="empty-state">
          A key belongs to one project. <Link to="/targets/new">Add a project</Link> first.
        </p>
      ) : (
        <form
          className="stack-form"
          onSubmit={(event) => {
            event.preventDefault();
            create.mutate();
          }}
        >
          <div className="auth-field">
            <label className="auth-field__label" htmlFor="key-project">
              Project
            </label>
            <select
              className="auth-field__input"
              id="key-project"
              onChange={(event) => setTargetId(event.target.value)}
              value={targetId}
            >
              {projects.map((project) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
          </div>

          <div className="auth-field">
            <label className="auth-field__label" htmlFor="account-key-name">
              Label <span className="dim">(optional)</span>
            </label>
            <input
              className="auth-field__input"
              id="account-key-name"
              onChange={(event) => setName(event.target.value)}
              placeholder="github-actions"
              type="text"
              value={name}
            />
          </div>

          <div className="auth-field">
            <label className="auth-field__label" htmlFor="account-key-scope">
              What this key can do
            </label>
            <select
              className="auth-field__input"
              id="account-key-scope"
              onChange={(event) => setScope(event.target.value)}
              value={scope}
            >
              {SCOPES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <p className="auth-field__hint">
              A key in CI is readable by anyone who can read a build log, so give it the
              least it needs.
            </p>
          </div>

          <div className="auth-actions">
            <Button disabled={create.isPending} type="submit" variant="secondary">
              {create.isPending ? "Creating…" : "Create key"}
            </Button>
          </div>
        </form>
      )}

      {keys.length > 0 ? (
        <div className="table-scroll u-mt-5">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Key</th>
                <th scope="col">Project</th>
                <th scope="col">Can do</th>
                <th scope="col">Last used</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr className={key.is_active ? undefined : "row--revoked"} key={key.id}>
                  <td>
                    <span className="mono">{key.prefix}…</span>
                    {key.name ? <span className="dim"> {key.name}</span> : null}
                  </td>
                  <td>{key.project ? key.project.name : "—"}</td>
                  <td>{SCOPES.find((entry) => entry.value === key.scope)?.label ?? key.scope}</td>
                  <td className="dim">
                    {!key.is_active
                      ? "Revoked " + (relativeTime(key.revoked_at) ?? "")
                      : (relativeTime(key.last_used_at) ?? "Never")}
                  </td>
                  <td className="u-right">
                    {key.is_active ? (
                      <Button
                        disabled={revoke.isPending}
                        onClick={() => revoke.mutate(key.id)}
                        variant="secondary"
                      >
                        Revoke
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
