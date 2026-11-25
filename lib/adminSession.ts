import "server-only";

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { getSupabaseAdmin } from "./supabaseAdmin";

export const ADMIN_COOKIE = "mindlet_admin";

function signingSecret() {
  const secret =
    process.env.ADMIN_SESSION_SECRET;
  if (!secret) throw new Error("관리자 세션 환경 변수가 설정되지 않았습니다.");
  return secret;
}

function hmacToken(token: string) {
  return createHmac("sha256", signingSecret()).update(token).digest("hex");
}

export function tokenHash(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export async function createAdminSessionToken() {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();
  const supabase = getSupabaseAdmin();
  const { error } = await supabase.from("admin_sessions").insert({
    token_hash: tokenHash(token),
    verification_hash: hmacToken(token),
    expires_at: expiresAt,
  });
  if (error) throw error;
  return token;
}

export async function isAdminRequest() {
  const token = (await cookies()).get(ADMIN_COOKIE)?.value;
  if (!token || token.length < 32) return false;

  const expected = hmacToken(token);
  const suppliedHash = tokenHash(token);
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase
    .from("admin_sessions")
    .select("verification_hash,expires_at")
    .eq("token_hash", suppliedHash)
    .maybeSingle();
  if (error || !data) return false;

  const left = Buffer.from(String(data.verification_hash));
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(left, right)) return false;

  return new Date(String(data.expires_at)).getTime() > Date.now();
}

export async function revokeAdminSession() {
  const token = (await cookies()).get(ADMIN_COOKIE)?.value;
  if (!token) return;
  await getSupabaseAdmin()
    .from("admin_sessions")
    .delete()
    .eq("token_hash", tokenHash(token));
}
