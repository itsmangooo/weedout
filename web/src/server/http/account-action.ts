import "server-only";

import { NextRequest, NextResponse } from "next/server";

import { AccountActionError } from "@/server/repositories/account-actions";
import { csrfFailure, errorResponse, validCsrf } from "./responses";

export function requireCsrf(request: NextRequest): NextResponse | null {
  return validCsrf(request) ? null : csrfFailure(request);
}

export function accountActionFailure(error: unknown, request: NextRequest) {
  if (error instanceof AccountActionError) {
    return errorResponse(error.status, error.code, error.message, request);
  }
  throw error;
}
