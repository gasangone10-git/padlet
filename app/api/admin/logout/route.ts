import { NextResponse } from "next/server";
import { ADMIN_COOKIE, revokeAdminSession } from "@/lib/adminSession";
import { hasSafeOrigin } from "@/lib/apiSecurity";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!hasSafeOrigin(request)) {
    return NextResponse.json({ error: "허용되지 않은 요청입니다." }, { status: 403 });
  }

  await revokeAdminSession();
  const response = NextResponse.json({ ok: true });
  response.cookies.set(ADMIN_COOKIE, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  });
  return response;
}
