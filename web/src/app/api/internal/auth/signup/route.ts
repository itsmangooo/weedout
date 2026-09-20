import { NextRequest } from "next/server";

import { authenticatedState } from "@/contracts/auth";
import { createSession, setSessionCookie } from "@/server/auth/lifecycle";
import { hashPassword, passwordProblem } from "@/server/auth/password";
import { db } from "@/server/db/client";
import { clientIp } from "@/server/http/client";
import { csrfFailure, errorResponse, privateResponse, validCsrf } from "@/server/http/responses";

type Created = { id: number; email: string; is_admin: boolean };
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function POST(request: NextRequest) {
  if (!validCsrf(request)) return csrfFailure(request);
  const body = await request.json().catch(() => ({})) as Record<string, unknown>;
  if (typeof body.website === "string" && body.website) {
    return privateResponse({ data: { authenticated: false, session_state: "anonymous", user: null } }, request);
  }
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (!emailPattern.test(email) || email.length > 320) return errorResponse(400, "INVALID_REQUEST", "Enter a valid email address.", request);
  const problem = passwordProblem(password);
  if (problem) return errorResponse(400, "WEAK_PASSWORD", problem, request);
  const passwordHash = await hashPassword(password);
  let created: Created;
  try {
    const rows = await db()<Created[]>`
      INSERT INTO users (email, password_hash, tier, is_admin)
      VALUES (${email}, ${passwordHash}, 'free', ${process.env.ADMIN_EMAIL?.trim().toLowerCase() === email})
      RETURNING id, email, is_admin
    `;
    created = rows[0];
  } catch (error) {
    if (String(error).includes("unique") || String(error).includes("duplicate")) {
      return errorResponse(409, "EMAIL_IN_USE", "That email address is already registered.", request);
    }
    throw error;
  }
  const token = await createSession(created.id, request.headers.get("user-agent"), clientIp(request));
  const response = privateResponse({
    data: authenticatedState({ id: created.id, email: created.email, is_admin: created.is_admin }),
    next: "/dashboard",
  }, request, { status: 201 });
  setSessionCookie(response, token);
  return response;
}
