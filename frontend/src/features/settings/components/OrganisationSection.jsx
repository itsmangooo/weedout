import { Buildings as Building2 } from "@phosphor-icons/react/Buildings";
import { useState } from "react";

import { setOrganisation, setShowcase } from "../../../api/settings";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { useSettingsMutation } from "../hooks/useSettings";

/**
 * Telling us this account is a company, and asking to be named for it.
 *
 * Two controls, and the copy has to keep them apart. The first changes nothing
 * — same plan, same limits, same everything — and saying so matters, because
 * an account type that people suspect of affecting their bill is one they
 * answer strategically.
 *
 * The second is the one to be careful with. Naming a company on our landing
 * page says publicly that they scan their dependencies with us, which is a
 * fact about their security programme and theirs to disclose. So the checkbox
 * says exactly what appears and where, asking is visibly not the same as being
 * listed, and turning it off is one click with no review.
 */

export function OrganisationSection({ account }) {
  const [name, setName] = useState(account.organisation_name ?? "");
  const [website, setWebsite] = useState(account.organisation_website ?? "");

  const save = useSettingsMutation(() => setOrganisation({ name, website }));
  const showcase = useSettingsMutation((listed) => setShowcase(listed));

  const isOrganisation = account.account_kind === "organization";
  const failure = save.error || showcase.error;

  return (
    <section aria-labelledby="org-title" className="settings-section">
      <h2 id="org-title">
        <Building2 aria-hidden="true" size={17} /> Company
      </h2>
      <p className="settings-section__lede">
        If this account belongs to a company, tell us here and invoices and emails will
        use the name. It changes nothing else — same plan, same limits.
      </p>

      {failure ? <InlineNotice tone="danger">{failure.message}</InlineNotice> : null}

      <form
        className="stack-form"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <div className="auth-field">
          <label className="auth-field__label" htmlFor="org-name">
            Company name
          </label>
          <input
            className="auth-field__input"
            id="org-name"
            onChange={(event) => setName(event.target.value)}
            placeholder="Acme Ltd"
            type="text"
            value={name}
          />
          <p className="auth-field__hint">Leave it empty for a personal account.</p>
        </div>

        <div className="auth-field">
          <label className="auth-field__label" htmlFor="org-website">
            Website
          </label>
          <input
            className="auth-field__input"
            id="org-website"
            onChange={(event) => setWebsite(event.target.value)}
            placeholder="https://acme.example"
            type="url"
            value={website}
          />
          <p className="auth-field__hint">
            Optional, and never shown unless you ask to be listed below.
          </p>
        </div>

        <div className="auth-actions">
          <Button disabled={save.isPending} type="submit" variant="secondary">
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </form>

      {isOrganisation ? (
        <>
          <h3 className="u-mt-6">Being named on our site</h3>
          <label className="toggle-row">
            <input
              checked={account.showcase_opt_in}
              disabled={showcase.isPending}
              onChange={(event) => showcase.mutate(event.target.checked)}
              type="checkbox"
            />
            <span>
              <strong>List {account.organisation_name} on the Weedout landing page.</strong>
              <small>
                Your company name and website appear in a short list of who uses Weedout.
                Nothing else — no logo, no project names, no findings, and never your
                email address.
              </small>
            </span>
          </label>

          {account.showcase_opt_in ? (
            <InlineNotice tone={account.showcase_listed ? "success" : "neutral"}>
              {account.showcase_listed ? (
                <>
                  {account.organisation_name} is listed. Untick the box above to remove it
                  — that takes effect immediately.
                </>
              ) : (
                <>
                  Thanks. We check that the name is yours to give before anything appears,
                  so it is not on the site yet. Untick the box at any time.
                </>
              )}
            </InlineNotice>
          ) : (
            <p className="auth-field__hint">
              Listing a company says publicly that they scan their dependencies with us,
              which is yours to disclose rather than ours. So this is off unless you turn
              it on.
            </p>
          )}
        </>
      ) : null}
    </section>
  );
}
