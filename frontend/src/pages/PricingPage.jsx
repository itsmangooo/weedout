import { Check } from "lucide-react";

import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { usePricing } from "../features/marketing/hooks/useMarketing";
import { Link } from "react-router";

/**
 * The plan table.
 *
 * Every word of it comes from app/tiers.py, the same module the limits are
 * enforced from. Nothing here is written twice, because a pricing page that
 * has drifted from the product is a promise nobody kept — and this one used to
 * advertise a feature that did not exist.
 */
export function PricingPage() {
  const query = usePricing();

  return (
    <div className="pricing-page public-editorial">
      <header className="page-head">
        <p className="section-label">Pricing</p>
        <h1>Everything Weedout ships is Free.</h1>
        <p className="page-head__lede">
          Dependency analysis, Node reachability evidence, custom rules, alerts, CLI,
          and CI behavior are included at no charge in the single Free product.
        </p>
      </header>

      <div className="pricing-detail">
      {query.isPending ? <AsyncLoading>Loading plans…</AsyncLoading> : null}
      {query.isError ? (
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      ) : null}

      {query.isSuccess ? (
        <div className="plan-grid">
          {query.data.plans.map((plan) => (
            <section className="plan-card" key={plan.id}>
              <header className="plan-intro"><div><p className="eyebrow">The whole product</p><h2>{plan.name}</h2></div><p className="plan-card__price">{plan.price}</p></header>
              <ul>
                {plan.features.map((feature) => (
                  <li key={feature}>
                    <Check aria-hidden="true" size={15} /> {feature}
                  </li>
                ))}
              </ul>
              <Link className="button button--primary" to="/signup">
                Create a free account
              </Link>
            </section>
          ))}
        </div>
      ) : null}
    </div></div>
  );
}
