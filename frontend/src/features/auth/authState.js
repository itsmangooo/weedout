import { ApiError } from "../../api/client";

export function authQueryState(query) {
  if (query.isPending) {
    return "loading";
  }

  if (query.isError) {
    if (
      query.error instanceof ApiError &&
      (query.error.status === 401 || query.error.code === "SESSION_EXPIRED")
    ) {
      return "expired";
    }
    if (query.error instanceof ApiError && query.error.status === 403) {
      return "forbidden";
    }
    return "unavailable";
  }

  return query.data.authenticated ? "authenticated" : "unauthenticated";
}

export function legacyLoginHref(location) {
  const next = `${location.pathname}${location.search}${location.hash}`;
  return `/login?next=${encodeURIComponent(next)}`;
}
