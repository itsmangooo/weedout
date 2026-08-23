import { ArrowUpRight, Flame, FolderOpen, Package, RadioTower } from "lucide-react";
import { motion } from "motion/react";
import { Link } from "react-router";

import { EntityContextMenu } from "../../../components/ui/EntityContextMenu";

const REACHABILITY_LABELS = {
  runtime_direct: "Direct runtime",
  runtime_transitive: "Transitive runtime",
  dev_only: "Development only",
};

function detectedLabel(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Detection time unavailable";

  return `Detected ${new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(date)}`;
}

export function FindingRow({ finding }) {
  const findingHref = `/alerts/${finding.id}`;
  const projectHref = `/targets/${finding.project.id}`;
  const menuItems = [
    { href: findingHref, icon: ArrowUpRight, label: "Open finding" },
    { href: projectHref, icon: FolderOpen, label: "Open project" },
  ];

  return (
    <EntityContextMenu items={menuItems} label={`Actions for finding ${finding.identifier}`}>
      <motion.li
        animate={{ opacity: 1, y: 0 }}
        className={`finding-row finding-row--${finding.severity}`}
        data-context-scope="finding"
        data-finding-id={finding.id}
        data-project-id={finding.project.id}
        initial={{ opacity: 0, y: 4 }}
        layout="position"
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="finding-row__identity">
          <Link to={findingHref}>{finding.identifier}</Link>
          <span className="finding-row__package">
            <Package aria-hidden="true" size={13} />
            {finding.package_name}@{finding.installed_version}
          </span>
        </div>

        <Link className="finding-row__project" to={projectHref}>
          {finding.project.name}
        </Link>

        <div className="finding-row__signals" aria-label="Finding signals">
          {finding.is_exploited ? (
            <span className="finding-signal finding-signal--exploited">
              <Flame aria-hidden="true" size={13} /> Exploited in the wild
            </span>
          ) : null}
          <span className={`finding-signal finding-signal--${finding.severity}`}>
            {finding.severity} severity
          </span>
          <span className="finding-signal">
            <RadioTower aria-hidden="true" size={13} />
            {REACHABILITY_LABELS[finding.reachability]}
          </span>
        </div>

        <div className="finding-row__state">
          <span>{finding.status}</span>
          <time dateTime={finding.detected_at}>{detectedLabel(finding.detected_at)}</time>
        </div>
      </motion.li>
    </EntityContextMenu>
  );
}
