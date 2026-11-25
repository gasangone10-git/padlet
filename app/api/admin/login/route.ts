import { NextResponse } from "next/server";
import { ADMIN_COOKIE, createAdminSessionToken } from "@/lib/adminSession";
import { verifyPassword } from "@/lib/password";
import { abuseKey, checkRateLimit, consumeRateLimit, hasSafeOrigin } from "@/lib/apiSecurity";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!hasSafeOrigin(request)) {
    return NextResponse.json({ error: "허용되지 않은 요청입니다." }, { status: 403 });
  }

  try {
    let body: Record<string, unknown>;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ error: "잘못된 JSON 요청입니다." }, { status: 400 });
    }

    if (!process.env.ADMIN_SESSION_SECRET) {
      return NextResponse.json(
        { error: "관리자 세션 설정을 확인해 주세요." },
        { status: 500 },
      );
    }

    const failureKey = abuseKey(request, "admin-login-failure");
    if (!(await checkRateLimit(failureKey, 15 * 60, 5))) {
      return NextResponse.json({ error: "잠시 후 다시 시도해 주세요." }, { status: 429 });
    }

    const adminHash = process.env.ADMIN_PASSWORD_HASH;

    if (typeof body.password !== "string") {
      return NextResponse.json(
        { error: "관리자 비밀번호를 입력해 주세요." },
        { status: 400 },
      );
    }

    if (!adminHash) {
      return NextResponse.json(
        { error: "관리자 설정을 확인해 주세요." },
        { status: 500 },
      );
    }

    const matches = await verifyPassword(body.password, adminHash);
    if (!matches) {
      await consumeRateLimit(failureKey, 15 * 60, 5);
      return NextResponse.json(
        { error: "관리자 비밀번호가 일치하지 않습니다." },
        { status: 401 },
      );
    }

    const sessionToken = await createAdminSessionToken();
    const response = NextResponse.json({ ok: true });
    response.cookies.set(ADMIN_COOKIE, sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: 60 * 60 * 8,
    });
    return response;
  } catch (error) {
    console.error("POST /api/admin/login", error);
    return NextResponse.json(
      { error: "관리자 로그인에 실패했습니다." },
      { status: 500 },
    );
  }
}
