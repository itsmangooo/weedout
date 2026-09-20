export function InlineNotice({ children, icon: Icon, title, tone = "neutral" }) {
  return (
    <div className={`inline-notice inline-notice--${tone}`} role={tone === "danger" ? "alert" : "status"}>
      {Icon ? <Icon aria-hidden="true" className="inline-notice__icon" size={20} strokeWidth={1.8} /> : null}
      <div>
        {title ? <p className="inline-notice__title">{title}</p> : null}
        <div className="inline-notice__body">{children}</div>
      </div>
    </div>
  );
}
