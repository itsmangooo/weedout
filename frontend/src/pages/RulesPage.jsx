import { AsyncError, AsyncLoading } from "../components/feedback/AsyncState";
import { PageFrame } from "../components/ui/PageFrame";
import { RuleProfiles } from "../features/settings/components/RuleProfiles";
import { useProfiles } from "../features/settings/hooks/useProfiles";

export function RulesPage() {
  const query = useProfiles();
  return <PageFrame className="rules-page" eyebrow="Workspace / policy" title="Rules" description="Keep deterministic scan policy in reusable profiles or in the repository with .weedout.yml.">
    <div className="rules-intro"><code>.weedout.yml</code><p>Repository rules take effect when the file is saved. Project settings override account defaults, and every decision retains its explanation.</p></div>
    {query.isPending && <AsyncLoading>Loading rule profiles…</AsyncLoading>}
    {query.isError && <AsyncError error={query.error} onRetry={() => query.refetch()} />}
    {query.isSuccess && <RuleProfiles meta={query.data.meta} profiles={query.data.data} />}
  </PageFrame>;
}
