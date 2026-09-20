export function PageFrame({ eyebrow, title, description, actions, children, className = "" }) {
  return <div className={`page-frame ${className}`}>
    <header className="page-heading">
      <div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{description && <p className="page-description">{description}</p>}</div>
      {actions && <div className="page-heading__actions">{actions}</div>}
    </header>
    {children}
  </div>;
}

export function DataMetric({ label, value, note, tone = "neutral" }) {
  return <div className={`data-metric data-metric--${tone}`}>
    <dt>{label}</dt><dd><span key={value} className="data-number">{value}</span></dd>{note && <small>{note}</small>}
  </div>;
}

export function SectionHeading({ index, title, children, id }) {
  return <div className="section-heading"><div>{index && <span className="eyebrow">{index}</span>}<h2 id={id}>{title}</h2></div>{children}</div>;
}
