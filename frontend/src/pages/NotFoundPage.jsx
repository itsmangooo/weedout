import { ArrowLeft } from "lucide-react";
import { Link } from "react-router";

import { PageTransition } from "../components/motion/PageTransition";

export function NotFoundPage() {
  return (
    <PageTransition>
      <div className="not-found mx-auto flex min-h-[70vh] w-full max-w-3xl flex-col justify-center px-6 py-16">
        <p className="eyebrow">404 · React route</p>
        <h1>This frontend route has not migrated yet.</h1>
        <p>
          React owns only the canonical dashboard. Every other Weedout product route remains with
          the Python application during this migration phase.
        </p>
        <Link className="text-link" to="/">
          <ArrowLeft aria-hidden="true" size={16} /> Return to the foundation
        </Link>
      </div>
    </PageTransition>
  );
}
