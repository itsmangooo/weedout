import { Outlet, useLocation } from "react-router";

import { authQueryState, legacyLoginHref } from "../authState";
import { useCurrentUser } from "../hooks/useCurrentUser";
import { AuthRouteState } from "./AuthRouteState";

export function ProtectedRoute() {
  const location = useLocation();
  const query = useCurrentUser();
  const state = authQueryState(query);

  if (state !== "authenticated") {
    return (
      <AuthRouteState
        loginHref={legacyLoginHref(location)}
        onRetry={() => query.refetch()}
        state={state}
      />
    );
  }

  return <Outlet />;
}
