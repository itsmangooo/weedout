export function SectionIndex({ items, label = "On this page" }) {
  return <nav className="section-index" aria-label={label}><p className="eyebrow">{label}</p>{items.map(([id, title], index) => <a key={id} href={`#${id}`}><span>{String(index + 1).padStart(2, "0")}</span>{title}</a>)}</nav>;
}
