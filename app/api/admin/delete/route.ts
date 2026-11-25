import { NextResponse } from "next/server";
import { isAdminRequest } from "@/lib/adminSession";
import { hasSafeOrigin, UUID_PATTERN } from "@/lib/apiSecurity";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!hasSafeOrigin(request)) {
    return NextResponse.json({ error: "허용되지 않은 요청입니다." }, { status: 403 });
  }

  if (!(await isAdminRequest())) {
    return NextResponse.json({ error: "관리자 인증이 필요합니다." }, { status: 401 });
  }

  try {
    let body: Record<string, unknown>;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ error: "잘못된 JSON 요청입니다." }, { status: 400 });
    }
    if (typeof body.id !== "string" || !UUID_PATTERN.test(body.id)) {
      return NextResponse.json({ error: "잘못된 요청입니다." }, { status: 400 });
    }

    const { error } = await getSupabaseAdmin()
      .from("memos")
      .delete()
      .eq("id", body.id);
    if (error) throw error;

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("POST /api/admin/delete", error);
    return NextResponse.json(
      { error: "메모를 강제 삭제하지 못했습니다." },
      { status: 500 },
    );
  }
}
