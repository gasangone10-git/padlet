import { NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";
import { isFourDigitPassword, verifyPassword } from "@/lib/password";
import { abuseKey, checkRateLimit, consumeRateLimit, hasSafeOrigin, UUID_PATTERN } from "@/lib/apiSecurity";

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
    if (
      typeof body.id !== "string" ||
      !UUID_PATTERN.test(body.id) ||
      !isFourDigitPassword(body.password)
    ) {
      return NextResponse.json(
        { error: "메모와 숫자 4자리 비밀번호를 확인해 주세요." },
        { status: 400 },
      );
    }

    const deleteAllowed = await consumeRateLimit(
      abuseKey(request, "memo-delete"),
      10 * 60,
      30,
    );
    if (!deleteAllowed) {
      return NextResponse.json({ error: "잠시 후 다시 시도해 주세요." }, { status: 429 });
    }

    const supabase = getSupabaseAdmin();
    const { data: memo, error: readError } = await supabase
      .from("memo_credentials")
      .select("password_hash")
      .eq("memo_id", body.id)
      .maybeSingle();

    if (readError) throw readError;
    if (!memo) {
      return NextResponse.json({ error: "메모를 찾을 수 없습니다." }, { status: 404 });
    }

    const failureKey = abuseKey(request, `memo-delete-failure:${body.id}`);
    const failuresAllowed = await checkRateLimit(failureKey, 10 * 60, 5);
    if (!failuresAllowed) {
      return NextResponse.json({ error: "잠시 후 다시 시도해 주세요." }, { status: 429 });
    }

    const matches = await verifyPassword(body.password, memo.password_hash);
    if (!matches) {
      await consumeRateLimit(failureKey, 10 * 60, 5);
      return NextResponse.json(
        { error: "삭제 비밀번호가 일치하지 않습니다." },
        { status: 403 },
      );
    }

    const { error: deleteError } = await supabase
      .from("memos")
      .delete()
      .eq("id", body.id);

    if (deleteError) throw deleteError;
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("POST /api/memos/delete", error);
    return NextResponse.json(
      { error: "메모를 삭제하지 못했습니다." },
      { status: 500 },
    );
  }
}
