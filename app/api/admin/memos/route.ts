import { NextResponse } from "next/server";
import { isAdminRequest } from "@/lib/adminSession";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";
import { hasSafeOrigin } from "@/lib/apiSecurity";

export const runtime = "nodejs";

export async function DELETE(request: Request) {
  if (!hasSafeOrigin(request)) {
    return NextResponse.json({ error: "허용되지 않은 요청입니다." }, { status: 403 });
  }
  if (!(await isAdminRequest())) {
    return NextResponse.json({ error: "관리자 인증이 필요합니다." }, { status: 401 });
  }

  try {
    const { error } = await getSupabaseAdmin().from("memos").delete().not("id", "is", null);
    if (error) throw error;

    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("DELETE /api/admin/memos", error);
    return NextResponse.json(
      { error: "전체 메모를 삭제하지 못했습니다." },
      { status: 500 },
    );
  }
}

export async function POST() {
  return NextResponse.json(
    { error: "이 경로는 DELETE 메서드를 사용해 주세요." },
    { status: 405 },
  );
}
