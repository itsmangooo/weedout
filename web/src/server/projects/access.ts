import "server-only";

import { db } from "@/server/db/client";

export async function ownsProject(userId: number, targetId: number) {
  const rows = await db()<Array<{ id: number }>>`SELECT id FROM tracked_targets WHERE id = ${targetId} AND user_id = ${userId} LIMIT 1`;
  return rows.length > 0;
}
