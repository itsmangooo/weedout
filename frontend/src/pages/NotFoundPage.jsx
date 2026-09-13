import { ArrowLeft, ArrowUpRight } from "lucide-react";
import { Link } from "react-router";
export function NotFoundPage() {
  return <section className="not-found public-editorial"><header><p className="eyebrow">404 / Page not found</p><h1>Nothing at<br />this address.</h1></header><div><p>The page may have moved, or the link may be incomplete.</p><div className="btn-row"><Link className="button button--primary" to="/"><ArrowLeft size={16} aria-hidden="true" />Return home</Link><Link className="text-link" to="/dashboard">Open your workspace <ArrowUpRight size={15} aria-hidden="true" /></Link></div></div></section>;
}
