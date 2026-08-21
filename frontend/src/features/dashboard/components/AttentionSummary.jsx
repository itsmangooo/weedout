import { ArrowRight, CircleCheck, Siren, TriangleAlert } from "lucide-react";
import { motion } from "motion/react";

function attentionState(summary) {
  if (summary.exploited_findings > 0) {
    return {
      icon: Siren,
      label: "Exploited in the wild",
      state: "exploited",
      value: summary.exploited_findings,
      note:
        summary.exploited_findings === 1
          ? "This finding appears on CISA's known-exploited list."
          : "These findings appear on CISA's known-exploited list.",
    };
  }

  if (summary.open_findings > 0) {
    return {
      icon: TriangleAlert,
      label: "Open findings",
      state: "open",
      value: summary.open_findings,
      note:
        summary.open_findings === 1
          ? "One finding cleared your alerting threshold."
          : "These findings cleared your alerting threshold.",
    };
  }

  return {
    icon: CircleCheck,
    label: "Nothing needs you",
    state: "clear",
    value: 0,
    note:
      summary.filtered_findings > 0
        ? `${summary.filtered_findings} matched advisories were filtered, not hidden.`
        : "No advisory currently matches your watched dependencies.",
  };
}

export function AttentionSummary({ summary }) {
  const attention = attentionState(summary);
  const Icon = attention.icon;

  return (
    <motion.section
      aria-labelledby="attention-heading"
      className={`attention-summary attention-summary--${attention.state}`}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
    >
      <h2 className="sr-only" id="attention-heading">
        Current attention state: {attention.label}
      </h2>
      <div className="attention-summary__body">
        <div className="attention-summary__signal">
          <Icon aria-hidden="true" size={20} strokeWidth={1.8} />
          <span>{attention.label}</span>
        </div>
        <div className="attention-summary__message">
          {attention.state === "clear" ? (
            <p className="attention-summary__clear">All clear</p>
          ) : (
            <p className="attention-summary__value">{attention.value}</p>
          )}
          <p className="attention-summary__note">{attention.note}</p>
          {summary.critical_findings > 0 ? (
            <p className="attention-summary__critical">
              {summary.critical_findings} critical open{" "}
              {summary.critical_findings === 1 ? "finding" : "findings"}
            </p>
          ) : null}
        </div>
        {summary.open_findings > 0 ? (
          <a className="button button--primary" href="/alerts?show=open">
            Review findings <ArrowRight aria-hidden="true" size={16} />
          </a>
        ) : null}
      </div>
    </motion.section>
  );
}
