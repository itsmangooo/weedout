import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  getAdminBilling,
  getAudit,
  getComposer,
  getDocPage,
  getDocPages,
  getInbox,
  getInboxMessage,
  getOverview,
  getUser,
  getUsers,
} from "../../../api/admin";

/**
 * Queries for the admin panel.
 *
 * All keyed under `["admin", …]` so a mutation can invalidate the whole panel
 * with one call when a change has effects it cannot enumerate — deleting an
 * account moves the user list, the metrics, the revenue snapshot and the audit
 * trail at once, and a mutation that only refreshed the list would leave three
 * screens quietly stale.
 */

export const adminKey = ["admin"];

export function useOverview(days = 30) {
  return useQuery({
    queryKey: [...adminKey, "overview", days],
    queryFn: ({ signal }) => getOverview({ days, signal }),
    staleTime: 15_000,
  });
}

export function useUsers(params) {
  return useQuery({
    queryKey: [...adminKey, "users", params],
    queryFn: ({ signal }) => getUsers({ ...params, signal }),
    // The list is read while acting on it — suspend somebody, come back, look
    // again — so a long stale window would show the state before the action.
    staleTime: 5_000,
    placeholderData: (previous) => previous,
  });
}

export function useUser(id) {
  return useQuery({
    queryKey: [...adminKey, "user", id],
    queryFn: ({ signal }) => getUser(id, { signal }),
    enabled: Boolean(id),
  });
}

export function useAdminBilling() {
  return useQuery({
    queryKey: [...adminKey, "billing"],
    queryFn: ({ signal }) => getAdminBilling({ signal }),
    staleTime: 30_000,
  });
}

export function useDocPages() {
  return useQuery({
    queryKey: [...adminKey, "docs"],
    queryFn: ({ signal }) => getDocPages({ signal }),
  });
}

export function useDocPage(id) {
  return useQuery({
    queryKey: [...adminKey, "doc", id],
    queryFn: ({ signal }) => getDocPage(id, { signal }),
    enabled: Boolean(id),
  });
}

export function useInbox(show = "new") {
  return useQuery({
    queryKey: [...adminKey, "inbox", show],
    queryFn: ({ signal }) => getInbox({ show, signal }),
    staleTime: 5_000,
  });
}

export function useInboxMessage(id) {
  const queryClient = useQueryClient();

  return useQuery({
    queryKey: [...adminKey, "message", id],
    queryFn: async ({ signal }) => {
      const payload = await getInboxMessage(id, { signal });
      // Opening a message marks it read, so the unread badge in the nav is
      // wrong the instant this resolves. Reading it is a mutation in
      // everything but name, which is why a plain query needs this.
      queryClient.invalidateQueries({ queryKey: [...adminKey, "inbox"] });
      return payload;
    },
    enabled: Boolean(id),
  });
}

export function useComposer() {
  return useQuery({
    queryKey: [...adminKey, "composer"],
    queryFn: ({ signal }) => getComposer({ signal }),
  });
}

export function useAudit() {
  return useQuery({
    queryKey: [...adminKey, "audit"],
    queryFn: ({ signal }) => getAudit({ signal }),
  });
}

/**
 * The unread badge in the nav.
 *
 * Reads the inbox query rather than adding a counter endpoint, so the badge
 * and the list can never disagree. It is deliberately allowed to be undefined
 * before the first inbox load — a badge that guesses is worse than one that
 * appears a moment later.
 */
export function useUnreadCount({ enabled = true } = {}) {
  const query = useQuery({
    queryKey: [...adminKey, "inbox", "new"],
    queryFn: ({ signal }) => getInbox({ show: "new", signal }),
    enabled,
    staleTime: 30_000,
  });

  return query.data?.unread ?? 0;
}

/**
 * Any change an admin makes, followed by a re-read of the whole panel.
 *
 * The blunt invalidation is the point: these actions have consequences across
 * screens that the call site has no way to list.
 */
export function useAdminMutation(mutationFn, options = {}) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn,
    ...options,
    onSuccess: async (...args) => {
      await queryClient.invalidateQueries({ queryKey: adminKey });
      await options.onSuccess?.(...args);
    },
  });
}
