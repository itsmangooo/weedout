import { KeyRound, ShieldAlert, Trash2 } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";

import {
  addIgnoreRule,
  createProjectKey,
  deleteProject,
  removeIgnoreRule,
  renameProject,
  revokeProjectKey,
  setThresholds,
} from "../../../api/projects";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { relativeTime } from "../../../lib/time";
import { useProjectMutation } from "../hooks/useProject";

const SCOPES = [
  { value: "scan", label: "Push scans — for CI" },
  { value: "read", label: "Read findings — for dashboards and the CLI" },
  { value: "manage", label: "Full access — including editing scan rules" },
];

const SEVERITIES = [
  { value: "", label: "Use the default" },
  { value: "critical", label: "Critical only" },
  { value: "high", label: "High and above" },
  { value: "medium", label: "Medium and above" },
  { value: "low", label: "Everything" },
];

export function ProjectSettings({ page, projectId }) {
  return (
    <div className="project-section project-settings">
      <RenameSection name={page.data.name} projectId={projectId} />
      <KeysSection keys={page.api_keys} projectId={projectId} />
      <RulesSection page={page} projectId={projectId} />
      <DangerSection name={page.data.name} projectId={projectId} />
    </div>
  );
}

function RenameSection({ name, projectId }) {
  const [value, setValue] = useState(name);
  const rename = useProjectMutation(projectId, () => renameProject(projectId, value));

  return (
    <section aria-labelledby="rename-title">
      <h2 id="rename-title">Name</h2>
      {rename.isError ? <InlineNotice tone="danger">{rename.error.message}</InlineNotice> : null}
      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          rename.mutate();
        }}
      >
        <label className="visually-hidden" htmlFor="project-name">
          Project name
        </label>
        <input
          className="auth-field__input"
          id="project-name"
          onChange={(event) => setValue(event.target.value)}
          type="text"
          value={value}
        />
        <Button disabled={rename.isPending || value === name} type="submit" variant="secondary">
          {rename.isPending ? "Saving…" : "Rename"}
        </Button>
      </form>
    </section>
  );
}

function KeysSection({ keys, projectId }) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState("scan");
  const [issued, setIssued] = useState(null);

  const create = useProjectMutation(
    projectId,
    () => createProjectKey(projectId, { name, scope }),
    { onSuccess: (data) => setIssued(data) },
  );
  const revoke = useProjectMutation(projectId, (keyId) => revokeProjectKey(projectId, keyId));

  return (
    <section aria-labelledby="keys-title">
      <h2 id="keys-title">
        <KeyRound aria-hidden="true" size={17} /> API keys
      </h2>

      {issued ? (
        <InlineNotice tone="success" title="Copy this now">
          <p className="mono selectable">{issued.token}</p>
          <p>
            This is the only time it is shown. Only its hash is stored, so if you lose
            it you will have to revoke the key and make another.
          </p>
        </InlineNotice>
      ) : null}

      {create.isError ? <InlineNotice tone="danger">{create.error.message}</InlineNotice> : null}

      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate();
        }}
      >
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="key-name">
            Label <span className="dim">(optional)</span>
          </label>
          <input
            className="auth-field__input"
            id="key-name"
            onChange={(event) => setName(event.target.value)}
            placeholder="github-actions"
            type="text"
            value={name}
          />
          <p className="auth-field__hint">Only so you can tell your keys apart later.</p>
        </div>

        <div className="auth-field">
          <label className="auth-field__label" htmlFor="key-scope">
            What this key can do
          </label>
          <select
            className="auth-field__input"
            id="key-scope"
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
            least it needs. Only pick full access for a key you keep yourself.
          </p>
        </div>

        <div className="auth-actions">
          <Button disabled={create.isPending} type="submit" variant="secondary">
            {create.isPending ? "Creating…" : "Create key"}
          </Button>
        </div>
      </form>

      {keys.length > 0 ? (
        <div className="table-scroll u-mt-5">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Key</th>
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
                  <td>{SCOPES.find((s) => s.value === key.scope)?.label ?? key.scope}</td>
                  <td className="dim">
                    {!key.is_active
                      ? `Revoked ${relativeTime(key.revoked_at) ?? ""}`
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

function RulesSection({ page, projectId }) {
  const [identifier, setIdentifier] = useState("");
  const [reason, setReason] = useState("");
  const [direct, setDirect] = useState(page.thresholds.direct ?? "");
  const [transitive, setTransitive] = useState(page.thresholds.transitive ?? "");

  const add = useProjectMutation(projectId, () => addIgnoreRule(projectId, { identifier, reason }), {
    onSuccess: () => {
      setIdentifier("");
      setReason("");
    },
  });
  const remove = useProjectMutation(projectId, (ruleId) => removeIgnoreRule(projectId, ruleId));
  const save = useProjectMutation(projectId, () =>
    setThresholds(projectId, { direct, transitive, epss: page.thresholds.epss }),
  );

  if (!page.can_use_rules) {
    return (
      <section aria-labelledby="rules-title">
        <h2 id="rules-title">Scan rules</h2>
        <InlineNotice tone="neutral">
          Custom thresholds and ignore rules are part of the Pro plan.{" "}
          <a href="/billing">See the plans</a>.
        </InlineNotice>
      </section>
    );
  }

  return (
    <section aria-labelledby="rules-title">
      <h2 id="rules-title">Scan rules</h2>

      <h3>Alert when</h3>
      {save.isError ? <InlineNotice tone="danger">{save.error.message}</InlineNotice> : null}
      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="direct">
            A direct dependency is affected
          </label>
          <select
            className="auth-field__input"
            id="direct"
            onChange={(event) => setDirect(event.target.value)}
            value={direct}
          >
            {SEVERITIES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="transitive">
            Something further down the tree is affected
          </label>
          <select
            className="auth-field__input"
            id="transitive"
            onChange={(event) => setTransitive(event.target.value)}
            value={transitive}
          >
            {SEVERITIES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div className="auth-actions">
          <Button disabled={save.isPending} type="submit" variant="secondary">
            {save.isPending ? "Saving…" : "Save thresholds"}
          </Button>
        </div>
      </form>

      <h3 className="u-mt-6">Ignored advisories</h3>
      {add.isError ? <InlineNotice tone="danger">{add.error.message}</InlineNotice> : null}

      {page.rules.length === 0 ? (
        <p className="empty-state">Nothing ignored. Every advisory that matches is reported.</p>
      ) : (
        <ul className="rule-list">
          {page.rules.map((rule) => (
            <li className="rule-row" key={rule.id}>
              <div>
                <p className="rule-row__id">{rule.identifier}</p>
                <p className="rule-row__reason">{rule.reason}</p>
                <p className="rule-row__meta">
                  {rule.created_by_email}
                  {rule.created_at ? ` · ${relativeTime(rule.created_at)}` : ""}
                </p>
                {rule.overridden_at ? (
                  <p className="rule-row__override">
                    <ShieldAlert aria-hidden="true" size={13} /> Being reported anyway: this
                    is on the known-exploited list.
                  </p>
                ) : null}
              </div>
              <Button
                disabled={remove.isPending}
                onClick={() => remove.mutate(rule.id)}
                variant="secondary"
              >
                Stop ignoring
              </Button>
            </li>
          ))}
        </ul>
      )}

      <form
        className="stack-form u-mt-4"
        onSubmit={(event) => {
          event.preventDefault();
          add.mutate();
        }}
      >
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="rule-id">
            Advisory
          </label>
          <input
            className="auth-field__input"
            id="rule-id"
            onChange={(event) => setIdentifier(event.target.value)}
            placeholder="CVE-2021-23337"
            type="text"
            value={identifier}
          />
        </div>
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="rule-reason">
            Why
          </label>
          <input
            className="auth-field__input"
            id="rule-reason"
            onChange={(event) => setReason(event.target.value)}
            placeholder="not reachable from our code"
            type="text"
            value={reason}
          />
          <p className="auth-field__hint">
            Required. A rule with no reason is indistinguishable from a mistake when you
            read it back in six months. An advisory that later turns up on the
            known-exploited list is reported anyway.
          </p>
        </div>
        <div className="auth-actions">
          <Button
            disabled={add.isPending || !identifier.trim() || !reason.trim()}
            type="submit"
            variant="secondary"
          >
            {add.isPending ? "Adding…" : "Ignore this advisory"}
          </Button>
        </div>
      </form>
    </section>
  );
}

function DangerSection({ name, projectId }) {
  const navigate = useNavigate();
  const [confirmation, setConfirmation] = useState("");

  const remove = useProjectMutation(projectId, () => deleteProject(projectId), {
    onSuccess: () => navigate("/dashboard"),
  });

  return (
    <section aria-labelledby="danger-title" className="danger-zone">
      <h2 id="danger-title">
        <Trash2 aria-hidden="true" size={17} /> Delete this project
      </h2>
      <p>
        Removes the project, its findings, its scan history and its keys. There is no
        undo, and anything still using one of its keys will start failing.
      </p>

      {remove.isError ? <InlineNotice tone="danger">{remove.error.message}</InlineNotice> : null}

      <form
        className="inline-form"
        onSubmit={(event) => {
          event.preventDefault();
          remove.mutate();
        }}
      >
        <label className="visually-hidden" htmlFor="confirm-delete">
          Type the project name to confirm
        </label>
        <input
          className="auth-field__input"
          id="confirm-delete"
          onChange={(event) => setConfirmation(event.target.value)}
          placeholder={`Type ${name} to confirm`}
          type="text"
          value={confirmation}
        />
        {/* Typing the name is the whole guard. A button that deletes on one
            click is one misclick away from losing a project's history. */}
        <Button disabled={remove.isPending || confirmation !== name} type="submit">
          {remove.isPending ? "Deleting…" : "Delete project"}
        </Button>
      </form>
    </section>
  );
}
