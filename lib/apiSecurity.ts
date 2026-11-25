import "server-only";

import { createHash } from "node:crypto";
import { getSupabaseAdmin } from "./supabaseAdmin";

export const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function hasSafeOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

export function getTrustedClientIp(request: Request) {
  const vercelForwarded = request.headers.get("x-vercel-forwarded-for");
  const candidate = vercelForwarded?.split(",")[0]?.trim();
  if (candidate) return candidate;

  if (process.env.NODE_ENV !== "production") {
    const forwarded = request.headers.get("x-forwarded-for");
    return forwarded?.split(",")[0]?.trim() || "127.0.0.1";
  }
  return "unknown";
}

export function abuseKey(request: Request, scope: string) {
  const ip = getTrustedClientIp(request);
  return createHash("sha256").update(`${ip}|${scope}`).digest("hex");
}

export async function consumeRateLimit(
  key: string,
  windowSeconds: number,
  limit: number,
) {
  const { data, error } = await getSupabaseAdmin().rpc("consume_abuse_limit", {
    p_key: key,
    p_window_seconds: windowSeconds,
    p_limit: limit,
  });
  if (error) throw error;
  return data === true;
}

export async function checkRateLimit(
  key: string,
  windowSeconds: number,
  limit: number,
) {
  const { data, error } = await getSupabaseAdmin().rpc("check_abuse_limit", {
    p_key: key,
    p_window_seconds: windowSeconds,
    p_limit: limit,
  });
  if (error) throw error;
  return data === true;
}
