export interface CurrentUser {
  id: number;
  email: string;
  is_admin: boolean;
  tier: "free";
  account_state: "active";
}

export type CurrentAuthState =
  | { authenticated: false; session_state: "anonymous"; user: null }
  | { authenticated: true; session_state: "authenticated"; user: CurrentUser };

export const anonymousAuthState = (): CurrentAuthState => ({
  authenticated: false,
  session_state: "anonymous",
  user: null,
});

export const authenticatedState = (user: Omit<CurrentUser, "tier" | "account_state">): CurrentAuthState => ({
  authenticated: true,
  session_state: "authenticated",
  user: { ...user, tier: "free", account_state: "active" },
});
