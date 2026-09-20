import { ArrowUpRight } from "@phosphor-icons/react/ArrowUpRight";
import { BracketsCurly } from "@phosphor-icons/react/BracketsCurly";
import { Code } from "@phosphor-icons/react/Code";
import { TerminalWindow } from "@phosphor-icons/react/TerminalWindow";

import { PageFrame } from "../components/ui/PageFrame";

const SOURCE = "https://github.com/itsmangooo/weedout";
const integrations = [
  { Icon: Code, name: "VS Code", status: "Available from source", href: `${SOURCE}/tree/main/integrations/vscode`, copy: "Starts with the workspace, watches dependency and rules files, and updates diagnostics, inline hints, hover context, and the Findings view." },
  { Icon: BracketsCurly, name: "JetBrains", status: "Available from source", href: `${SOURCE}/tree/main/integrations/jetbrains`, copy: "Uses native project listeners, editor annotations, inlay hints, hover details, and a Weedout tool window with equivalent automatic behavior." },
  { Icon: TerminalWindow, name: "CLI", status: "Work in progress", href: "/cli", copy: "A secondary terminal and CI workflow. Automatic IDE analysis is the primary product experience." },
];

export function IntegrationsPage() {
  return <PageFrame className="integrations-page" eyebrow="Workspace / connected tools" title="Integrations" description="Weedout follows dependency changes in the tools where development already happens.">
    <div className="integration-list">{integrations.map(({ Icon, name, status, href, copy }) => <article key={name}><Icon size={23} weight="duotone" /><div><h2>{name}</h2><p>{copy}</p><code>Auth · Rules · Create Project · Delete Project</code></div><div><span>{status}</span><a className="button button--secondary" href={href} target={href.startsWith("http") ? "_blank" : undefined} rel={href.startsWith("http") ? "noopener noreferrer" : undefined}>{name === "CLI" ? "View status" : `Install ${name}`} <ArrowUpRight size={14} /></a></div></article>)}</div>
  </PageFrame>;
}
