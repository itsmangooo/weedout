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
    <div className="page-narrow">
      <header className="page-head">
        <p className="section-label">Pricing</p>
        <h1>One free project. Everything else on one plan.</h1>
        <p className="page-head__lede">
          Both plans use the same matching and the same filtering. Paying does not
          change which vulnerabilities you are shown — it changes how many projects
          you can watch, how often, and how deep.
        </p>
      </header>

      {query.isPending ? <AsyncLoading>Loading plans…</AsyncLoading> : null}
      {query.isError ? (
        <AsyncError error={query.error} onRetry={() => query.refetch()} />
      ) : null}

      {query.isSuccess ? (
        <div className="plan-grid">
          {query.data.plans.map((plan) => (
            <section className="plan-card" key={plan.id}>
              <h2>{plan.name}</h2>
              <p className="plan-card__price">{plan.price}</p>
              <ul>
                {plan.features.map((feature) => (
                  <li key={feature}>
                    <Check aria-hidden="true" size={15} /> {feature}
                  </li>
                ))}
              </ul>
              <Link className="button button--primary" to="/signup">
                Start with {plan.name}
              </Link>
            </section>
          ))}
        </div>
      ) : null}
    </div>
  );
}
