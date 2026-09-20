import { Laptop } from "@phosphor-icons/react/Laptop";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { getSignedInMachines, revokeMachine } from "../../../api/cliAuth";
import { Button } from "../../../components/ui/Button";
import { InlineNotice } from "../../../components/ui/InlineNotice";
import { relativeTime } from "../../../lib/time";

/**
 * Machines that ran `weedout auth`.
 *
 * The other half of that flow being worth anything: a login you can grant and
 * cannot see afterwards is a login you cannot take back. This is also where
 * somebody notices a machine they do not recognise, so the device label — which
 * the machine chose for itself — is shown with the fact that we did not verify
 * it, and the last-used time is given prominence, because "a laptop I sold in
 * March, last used yesterday" is the sentence that matters.
 */

const machinesQueryKey = ["cli-tokens"];

export function SignedInMachines() {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: machinesQueryKey,
    queryFn: ({ signal }) => getSignedInMachines({ signal }),
    staleTime: 15_000,
  });

  const revoke = useMutation({
    mutationFn: (id) => revokeMachine(id),
    onSuccess: () => client.invalidateQueries({ queryKey: machinesQueryKey }),
  });

  if (!query.isSuccess) return null;

  const machines = query.data.data;

  return (
    <section aria-labelledby="machines-title" className="settings-section">
      <h2 id="machines-title">
        <Laptop aria-hidden="true" size={17} /> Signed-in machines
      </h2>
      <p className="settings-section__lede">
        Copies of the CLI that can create projects and issue keys for them on this
        account. They cannot read findings or push a scan — that needs a project key.
      </p>

      {revoke.isError ? <InlineNotice tone="danger">{revoke.error.message}</InlineNotice> : null}

      {machines.length === 0 ? (
        <p className="empty-state">
          None. Run <code>weedout auth</code> to sign one in.
        </p>
      ) : (
        <ul className="rule-list">
          {machines.map((machine) => (
            <li className="rule-row" key={machine.id}>
              <div>
                <p className="rule-row__id">
                  {machine.device_label || "An unnamed machine"}
                </p>
                <p className="rule-row__reason">
                  {machine.last_used_at
                    ? `Last used ${relativeTime(machine.last_used_at)}`
                    : "Never used"}
                </p>
                <p className="rule-row__meta">
                  Signed in {relativeTime(machine.created_at)} · expires{" "}
                  {relativeTime(machine.expires_at)}
                </p>
              </div>
              <Button
                disabled={revoke.isPending}
                onClick={() => revoke.mutate(machine.id)}
                variant="secondary"
              >
                Sign it out
              </Button>
            </li>
          ))}
        </ul>
      )}

      {machines.length > 0 ? (
        <p className="auth-field__hint">
          The name is whatever the machine called itself, so it is a label rather than
          proof. If one looks wrong, sign it out — the CLI on that machine will ask to be
          approved again next time it runs.
        </p>
      ) : null}
    </section>
  );
}
