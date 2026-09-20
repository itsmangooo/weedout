import { createHash } from "node:crypto";
import { NextRequest } from "next/server";
import { scan } from "@/server/engine/client";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { ecosystemFor, manifestKind } from "@/server/projects/manifest";
import { scanProject } from "@/server/projects/scan";

export async function POST(request: NextRequest, { params }: { params: Promise<{ targetId: string }> }) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request); if ("response" in auth) return auth.response;
  const targetId = Number((await params).targetId);
  const targets = await db()<Array<{ ecosystem: string }>>`SELECT ecosystem FROM tracked_targets WHERE id = ${targetId} AND user_id = ${auth.user.id}`;
  if (!targets.length) return errorResponse(404, "NOT_FOUND", "That project doesn't exist.", request);
  const form = await request.formData();
  const upload = form.get("manifest");
  let content = String(form.get("content") ?? "");
  let filename = String(form.get("filename") ?? "").trim();
  if (upload instanceof File && upload.name) { content = await upload.text(); filename = upload.name; }
  const kind = manifestKind(filename);
  if (!kind || !content.trim()) return errorResponse(400, "UNSUPPORTED", "Could not recognise that dependency manifest.", request);
  const ecosystem = ecosystemFor(kind);
  if (ecosystem !== targets[0].ecosystem) return errorResponse(400, "UNSUPPORTED", `This project tracks ${targets[0].ecosystem} dependencies, but that file is ${ecosystem}.`, request);
  try { await scan({ manifests: [{ path: filename, kind, ecosystem, content }] }); } catch (error) { return errorResponse(400, "UNSUPPORTED", String(error), request); }
  const digest = createHash("sha256").update(content).digest("hex");
  const manifests = await db()<Array<{ id: number }>>`SELECT id FROM project_manifests WHERE target_id = ${targetId} AND is_active ORDER BY id LIMIT 1`;
  if (manifests.length) {
    await db()`UPDATE project_manifests SET path = ${filename.slice(0, 400)}, kind = ${kind}, content = ${content}, content_hash = ${digest}, updated_at = now() WHERE id = ${manifests[0].id}`;
  } else {
    await db()`INSERT INTO project_manifests (target_id, path, kind, ecosystem, content, content_hash, dependency_count, is_active) VALUES (${targetId}, ${filename.slice(0, 400)}, ${kind}, ${ecosystem}, ${content}, ${digest}, 0, true)`;
  }
  await db()`UPDATE tracked_targets SET manifest_kind = ${kind}, manifest_content = ${content}, content_hash = ${digest}, updated_at = now() WHERE id = ${targetId}`;
  await scanProject(targetId, auth.user.id);
  const rows = await db()<Array<{ dependency_count: number }>>`SELECT dependency_count FROM tracked_targets WHERE id = ${targetId}`;
  return privateResponse({ data: { id: targetId, dependency_count: rows[0].dependency_count } }, request);
}
