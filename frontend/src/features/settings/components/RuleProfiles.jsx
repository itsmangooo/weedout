import { SlidersHorizontal } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import {
  createProfile,
  deleteProfile,
  makeProfileDefault,
  saveProfile,
} from "../../../api/profiles";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { relativeTime } from "../../../lib/time";
import { useProfilesMutation } from "../hooks/useProfiles";

/**
 * A profile is a `.weedout.yml` document under a name, so the editor is a text
 * area rather than a form of typed fields.
 *
 * That is a choice, not a shortcut. The syntax already exists, is already
 * documented, and is already what people write in their repositories — a
 * parallel set of dropdowns would be a second model of the same thing, and the
 * two would drift. It also means a working file can become a shared standard
 * by being pasted in.
 */

const STARTER = `severity:
  direct: high
  transitive: critical

# ignore:
#   - cve: CVE-2021-23337
#     reason: Not reachable from any entry point we ship.
`;

export function RuleProfiles({ profiles, meta }) {
  const [editing, setEditing] = useState(null);

  return (
    <section aria-labelledby="profiles-title" className="settings-section">
      <h2 id="profiles-title">
        <SlidersHorizontal aria-hidden="true" size={17} /> Rule profiles
      </h2>
      <p className="settings-section__lede">
        One set of scan rules, written once and used by any project. A project can pick
        a profile, or follow the account default. Rules in a project&rsquo;s own settings,
        and in its <code>.weedout.yml</code>, still win.
      </p>

      {profiles.length === 0 ? (
        <p className="empty-state">
          No profiles. Every project uses its own settings and the built-in rules.
        </p>
      ) : (
        <ul className="profile-list">
          {profiles.map((profile) => (
            <ProfileRow
              key={profile.id}
              onEdit={() => setEditing(profile.id)}
              onDone={() => setEditing(null)}
              open={editing === profile.id}
              profile={profile}
            />
          ))}
        </ul>
      )}

      {profiles.length < meta.limit ? (
        <NewProfile onCreated={(created) => setEditing(created?.id ?? null)} />
      ) : (
        <p className="auth-field__hint">
          That is {meta.limit} profiles, which is the limit. Edit one of the existing
          ones instead.
        </p>
      )}
    </section>
  );
}

function ProfileRow({ profile, open, onEdit, onDone }) {
  const [name, setName] = useState(profile.name);
  const [description, setDescription] = useState(profile.description);
  const [document, setDocument] = useState(profile.document);

  const save = useProfilesMutation(
    () => saveProfile(profile.id, { name, description, document }),
    { onSuccess: onDone },
  );
  const makeDefault = useProfilesMutation(() => makeProfileDefault(profile.id));
  const remove = useProfilesMutation(() => deleteProfile(profile.id));

  const failure = save.error || makeDefault.error || remove.error;

  return (
    <li className="profile-row">
      <div className="profile-row__head">
        <div>
          <p className="profile-row__name">
            {profile.name}
            {profile.is_default ? (
              <span className="profile-row__flag">account default</span>
            ) : null}
          </p>
          <p className="profile-row__meta">
            <code>{profile.slug}</code>
            {profile.description ? ` · ${profile.description}` : ""}
          </p>
          <p className="profile-row__meta">
            {profile.used_by === 0
              ? "No project has chosen this one."
              : `Chosen by ${profile.used_by} project${profile.used_by === 1 ? "" : "s"}.`}
            {profile.updated_at ? ` Edited ${relativeTime(profile.updated_at)}.` : ""}
          </p>
        </div>
        <div className="profile-row__actions">
          <Button onClick={open ? onDone : onEdit} variant="secondary">
            {open ? "Close" : "Edit"}
          </Button>
        </div>
      </div>

      {failure ? <InlineNotice tone="danger">{failure.message}</InlineNotice> : null}

      {open ? (
        <form
          className="stack-form"
          onSubmit={(event) => {
            event.preventDefault();
            save.mutate();
          }}
        >
          <div className="auth-field">
            <label className="auth-field__label" htmlFor={`profile-name-${profile.id}`}>
              Name
            </label>
            <input
              className="auth-field__input"
              id={`profile-name-${profile.id}`}
              onChange={(event) => setName(event.target.value)}
              type="text"
              value={name}
            />
            <p className="auth-field__hint">
              Renaming changes what <code>--profile</code> matches, so a pipeline naming
              the old one will start failing.
            </p>
          </div>

          <div className="auth-field">
            <label className="auth-field__label" htmlFor={`profile-desc-${profile.id}`}>
              What it is for
            </label>
            <input
              className="auth-field__input"
              id={`profile-desc-${profile.id}`}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Everything customer-facing"
              type="text"
              value={description}
            />
          </div>

          <div className="auth-field">
            <label className="auth-field__label" htmlFor={`profile-doc-${profile.id}`}>
              Rules
            </label>
            <textarea
              className="auth-field__input auth-field__input--document"
              id={`profile-doc-${profile.id}`}
              onChange={(event) => setDocument(event.target.value)}
              rows={12}
              spellCheck={false}
              value={document}
            />
            <p className="auth-field__hint">
              The same syntax as <code>.weedout.yml</code>.{" "}
              <Link to="/docs/scan-rules">Every key it takes</Link>. Saved only if it
              parses.
            </p>
          </div>

          <div className="auth-actions">
            <Button disabled={save.isPending} type="submit" variant="secondary">
              {save.isPending ? "Saving…" : "Save changes"}
            </Button>
            {profile.is_default ? null : (
              <Button
                disabled={makeDefault.isPending}
                onClick={() => makeDefault.mutate()}
                type="button"
                variant="secondary"
              >
                Make it the default
              </Button>
            )}
            <Button
              disabled={remove.isPending}
              onClick={() => remove.mutate()}
              type="button"
              variant="danger"
            >
              Delete
            </Button>
          </div>
          <p className="auth-field__hint">
            Deleting moves any project using this profile to the account default.
          </p>
        </form>
      ) : null}
    </li>
  );
}

function NewProfile({ onCreated }) {
  const [name, setName] = useState("");

  const create = useProfilesMutation(() => createProfile({ name, document: STARTER }), {
    onSuccess: (created) => {
      setName("");
      onCreated(created);
    },
  });

  return (
    <form
      className="stack-form u-mt-4"
      onSubmit={(event) => {
        event.preventDefault();
        create.mutate();
      }}
    >
      {create.isError ? (
        <InlineNotice tone="danger">{create.error.message}</InlineNotice>
      ) : null}
      <div className="auth-field">
        <label className="auth-field__label" htmlFor="new-profile">
          New profile
        </label>
        <input
          className="auth-field__input"
          id="new-profile"
          onChange={(event) => setName(event.target.value)}
          placeholder="Production"
          type="text"
          value={name}
        />
        <p className="auth-field__hint">
          It starts with the default rules, and opens for editing. The first profile you
          make becomes the account default.
        </p>
      </div>
      <div className="auth-actions">
        <Button disabled={create.isPending || !name.trim()} type="submit" variant="secondary">
          {create.isPending ? "Creating…" : "Create profile"}
        </Button>
      </div>
    </form>
  );
}
