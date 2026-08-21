export function Button({ className = "", type = "button", variant = "primary", ...props }) {
  const classes = ["button", `button--${variant}`, className].filter(Boolean).join(" ");
  return <button className={classes} type={type} {...props} />;
}
