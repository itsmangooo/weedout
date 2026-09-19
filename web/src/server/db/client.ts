import "server-only";

import postgres from "postgres";

let client: ReturnType<typeof postgres> | undefined;

function databaseURL() {
  const value = process.env.DATABASE_URL;
  if (!value) throw new Error("DATABASE_URL is required for database operations");
  return value.replace(/^postgresql\+psycopg:/, "postgresql:");
}

// During migration both applications use the existing PostgreSQL schema. New
// Next.js repositories must use explicit transactions and preserve current IDs.
export function db() {
  client ??= postgres(databaseURL(), {
    max: Number(process.env.DATABASE_POOL_SIZE ?? 10),
    idle_timeout: 20,
    connect_timeout: 10,
    prepare: false,
  });
  return client;
}
