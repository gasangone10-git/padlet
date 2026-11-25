import { NextResponse } from "next/server";
import { isAdminRequest } from "@/lib/adminSession";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";
import { hasSafeOrigin, UUID_PATTERN } from "@/lib/apiSecurity";

export const runtime = "nodejs";

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  if (!hasSafeOrigin(_request)) {
    return NextResponse.json({ error: "허용되지 않은 요청입니다." }, { status: 403 });
  }
  if (!(await isAdminRequest())) {
    return NextResponse.json({ error: "관리자 인증이 필요합니다." }, { status: 401 });
  }

  const { id } = await params;
  if (!UUID_PATTERN.test(id)) {
    return NextResponse.json({ error: "잘못된 요청입니다." }, { status: 400 });
  }

  try {
    const { error } = await getSupabaseAdmin().from("memos").delete().eq("id", id);
    if (error) throw error;
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("DELETE /api/admin/memos/[id]", error);
    return NextResponse.json(
      { error: "메모를 강제 삭제하지 못했습니다." },
      { status: 500 },
    );
  }
}

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  return DELETE(request, context);
}
