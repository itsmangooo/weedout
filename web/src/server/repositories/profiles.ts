import "server-only";

import { db } from "@/server/db/client";
import { number } from "@/server/http/responses";

type ProfileRow = {
  id: number;
  name: string;
  slug: string;
  description: string;
  document: string;
  is_default: boolean;
  updated_at: Date | null;
  used_by: string | number;
};

export async function profilesFor(userId: number) {
  const rows = await db()<ProfileRow[]>`
    SELECT p.id, p.name, p.slug, p.description, p.document, p.is_default,
           p.updated_at, count(t.id) AS used_by
    FROM rule_profiles p
    LEFT JOIN tracked_targets t ON t.profile_id = p.id AND t.user_id = p.user_id
    WHERE p.user_id = ${userId}
    GROUP BY p.id
    ORDER BY p.is_default DESC, p.name
  `;
  return {
    data: rows.map((row) => ({ ...row, used_by: number(row.used_by) })),
    meta: { limit: 20, can_use_profiles: true },
  };
}
