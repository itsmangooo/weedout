import { createHash } from "node:crypto";
import { NextRequest } from "next/server";

import { scan } from "@/server/engine/client";
import { db } from "@/server/db/client";
import { authenticated, csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";
import { ecosystemFor, manifestKind } from "@/server/projects/manifest";
import { scanProject } from "@/server/projects/scan";

const MAX_MANIFEST_BYTES = Number(process.env.MAX_MANIFEST_BYTES ?? 5 * 1024 * 1024);
const ecosystems = new Set(["npm", "PyPI", "Go", "crates.io", "Maven"]);

export async function POST(request: NextRequest) {
  if (!validCsrf(request)) return csrfFailure(request);
  const auth = await authenticated(request);
  if ("response" in auth) return auth.response;
  const form = await request.formData();
  const name = String(form.get("name") ?? "").trim().slice(0, 200);
  const upload = form.get("manifest");
  let content = String(form.get("content") ?? "");
  let filename = String(form.get("filename") ?? "").trim();
  if (upload instanceof File && upload.name) {
    if (upload.size > MAX_MANIFEST_BYTES) return errorResponse(413, "TOO_LARGE", `That file is larger than ${Math.floor(MAX_MANIFEST_BYTES / 1024 / 1024)} MB.`, request);
    content = await upload.text();
    filename = upload.name;
  }
  if (!content.trim()) {
    const ecosystem = String(form.get("ecosystem") ?? "");
    if (!name) return errorResponse(400, "INVALID_REQUEST", "Give the project a name.", request);
    if (!ecosystems.has(ecosystem)) return errorResponse(400, "INVALID_REQUEST", "Choose a supported ecosystem.", request);
    const rows = await db()<Array<{ id: number; name: string }>>`
      INSERT INTO tracked_targets (user_id, name, ecosystem, dependency_count, is_active)
      VALUES (${auth.user.id}, ${name}, ${ecosystem}, 0, true) RETURNING id, name
    `;
    return privateResponse({ data: { ...rows[0], scanned: false } }, request, { status: 201 });
  }
  if (Buffer.byteLength(content, "utf8") > MAX_MANIFEST_BYTES) return errorResponse(413, "TOO_LARGE", `That file is larger than ${Math.floor(MAX_MANIFEST_BYTES / 1024 / 1024)} MB.`, request);
  const kind = manifestKind(filename);
  if (!kind) return errorResponse(400, "UNSUPPORTED", "Could not recognise that file. Use a supported dependency manifest.", request);
  const ecosystem = ecosystemFor(kind);
  try {
    const result = await scan({ manifests: [{ path: filename, kind, ecosystem, content }] });
    if (!result.graph.dependencies.length) return errorResponse(400, "UNSUPPORTED", "No dependencies with checkable versions were found in that file.", request);
  } catch (error) {
    return errorResponse(400, "UNSUPPORTED", String(error).replace(/^Error:\s*/, ""), request);
  }
  const displayName = name || filename || kind;
  const targetRows = await db()<Array<{ id: number; name: string }>>`
    INSERT INTO tracked_targets (user_id, name, ecosystem, manifest_kind, manifest_content, content_hash, dependency_count, is_active)
    VALUES (${auth.user.id}, ${displayName.slice(0, 200)}, ${ecosystem}, ${kind}, ${content},
            ${createHash("sha256").update(content).digest("hex")}, 0, true)
    RETURNING id, name
  `;
  const target = targetRows[0];
  await db()`
    INSERT INTO project_manifests (target_id, path, kind, ecosystem, content, content_hash, dependency_count, is_active)
    VALUES (${target.id}, ${filename.slice(0, 400)}, ${kind}, ${ecosystem}, ${content},
            ${createHash("sha256").update(content).digest("hex")}, 0, true)
  `;
  let scanned = true;
  try { await scanProject(target.id, auth.user.id); } catch { scanned = false; }
  return privateResponse({ data: { id: target.id, name: target.name, scanned } }, request, { status: 201 });
}
