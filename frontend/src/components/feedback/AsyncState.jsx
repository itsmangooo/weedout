import { CircleNotch as LoaderCircle } from "@phosphor-icons/react/CircleNotch";
import { CloudSlash as ServerOff } from "@phosphor-icons/react/CloudSlash";

import { Button } from "../ui/Button";
import { InlineNotice } from "../ui/InlineNotice";

export function AsyncLoading({ children = "Loading…" }) {
  return (
    <InlineNotice icon={LoaderCircle} title="Checking connection">
      <p>{children}</p>
    </InlineNotice>
  );
}

export function AsyncError({ error, onRetry }) {
  return (
    <div className="async-error">
      <InlineNotice icon={ServerOff} title="Backend unavailable" tone="danger">
        <p>{error?.message || "The service did not answer."}</p>
      </InlineNotice>
      {onRetry ? (
        <Button onClick={onRetry} variant="secondary">
          Try again
        </Button>
      ) : null}
    </div>
  );
}
