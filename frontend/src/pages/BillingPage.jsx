import { CreditCard, ExternalLink } from "lucide-react";
import { useLocation, useSearchParams } from "react-router";

import { api } from "../api/client";
import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { InlineNotice } from "../components/ui/InlineNotice";
import { useQuery } from "@tanstack/react-query";
import { relativeTime } from "../lib/time";

function useBilling() {
  return useQuery({
    queryKey: ["billing"],
    queryFn: async ({ signal }) => {
      const payload = await api("/api/internal/billing", { signal });
      return payload?.data;
    },
    staleTime: 15_000,
  });
}

export function BillingPage() {
  const [params] = useSearchParams();
  const location = useLocation();
  const query = useBilling();

  // Dodo returns people to /billing/success after checkout — an address baked
  // into every checkout link already issued, which is why it survived the
  // migration rather than becoming a query parameter. The query form is
  // accepted too, so a link written either way lands somewhere sensible.
  //
  // Either way this says "processing" rather than confirming: the webhook is
  // what actually grants the plan and may not have arrived. Being contradicted
  // a second later is worse than waiting a second.
  const justCheckedOut =
    location.pathname.endsWith("/success") || params.get("checkout") === "success";

  if (query.isPending) {
    return (
      <div className="page-narrow">
        <AsyncLoading>Loading your plan…</AsyncLoading>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="page-narrow">
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      </div>
    );
  }

  const billing = query.data;

  return (
    <div className="page-narrow">
      <header className="page-head">
        <p className="section-label">Billing</p>
        <h1>You are on the {billing.plan_name} plan.</h1>
      </header>

      {justCheckedOut && !billing.is_pro ? (
        <div className="u-mb-5">
          <InlineNotice tone="neutral" title="Payment received — finishing up">
            Your upgrade is being applied. It usually takes a few seconds; refresh if
            this is still here in a minute.
          </InlineNotice>
        </div>
      ) : null}

      {justCheckedOut && billing.is_pro ? (
        <div className="u-mb-5">
          <InlineNotice tone="success" title="You are on Pro">
            Unlimited projects, checked every four hours, the whole dependency tree.
          </InlineNotice>
        </div>
      ) : null}

      {billing.is_pro ? <ProPanel billing={billing} /> : <UpgradePanel billing={billing} />}
    </div>
  );
}

function ProPanel({ billing }) {
  return (
    <section className="settings-section">
      <h2>
        <CreditCard aria-hidden="true" size={17} /> Pro
      </h2>

      <dl className="billing-facts">
        <div>
          <dt>Status</dt>
          <dd>{billing.subscription_status || "active"}</dd>
        </div>
        {billing.subscription_ends_at ? (
          <div>
            <dt>Next billed</dt>
            <dd>{relativeTime(billing.subscription_ends_at)}</dd>
          </div>
        ) : null}
      </dl>

      <p className="auth-field__hint">
        Manage or cancel from the receipt Dodo emailed you. Changes appear here within
        a minute.
      </p>
    </section>
  );
}

function UpgradePanel({ billing }) {
  if (!billing.checkout_enabled) {
    return (
      <section className="settings-section">
        <h2>Checkout is not configured</h2>
        {/* Self-hosted instances have no Dodo credentials. Saying so beats a
            button that goes nowhere. */}
        <InlineNotice tone="neutral">
          This deployment cannot take payments. Set <code>DODO_ENABLED=true</code> with
          the Dodo API key, webhook secret and product id.
        </InlineNotice>
      </section>
    );
  }

  return (
    <section className="settings-section">
      <h2>
        <CreditCard aria-hidden="true" size={17} /> Upgrade to Pro
      </h2>
      <p className="settings-section__lede">
        Unlimited projects, checked every four hours, the whole dependency tree however
        deep, and full alert history.
      </p>

      {billing.checkout_url ? (
        <div className="settings-actions">
          {/* A plain link to Dodo's hosted checkout. No embedded SDK, so
              nothing third-party runs on this page and the CSP stays strict. */}
          <a
            className="button button--primary"
            href={billing.checkout_url}
            rel="noopener"
          >
            Continue to checkout <ExternalLink aria-hidden="true" size={15} />
          </a>
        </div>
      ) : (
        <InlineNotice tone="neutral">
          No product is configured for the Pro plan yet.
        </InlineNotice>
      )}

      <p className="auth-field__hint">
        Dodo Payments handles payment and tax as merchant of record. Your card details
        never reach our servers.
      </p>
    </section>
  );
}
