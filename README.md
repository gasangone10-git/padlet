# MINDLET

Next.js, Supabase, Vercel 기반의 개인용 메모 보드입니다. 섹션·컬럼·카테고리 없이 메모 카드만 자유롭게 쌓습니다.

## 로컬 실행

1. Node.js 22 이상과 npm 버전을 확인합니다.
2. 신규 DB는 Supabase SQL Editor에서 `schema.sql`을 실행하고, 기존 DB는 먼저 구조 확인 SQL을 확인한 뒤 `migration.sql`을 적용합니다.
3. `.env.example`을 `.env.local`로 복사하고 참여자 자신의 Supabase 값을 채웁니다.
3. 관리자 비밀번호 해시는 아래처럼 생성합니다.

```bash
node -e "require('bcryptjs').hash(process.argv[1], 12).then(console.log)" "원하는-관리자-비밀번호"
```

4. `ADMIN_SESSION_SECRET`에는 길고 무작위인 문자열을 넣습니다.
5. 개발 서버를 실행합니다.

```bash
npm run dev
```

## 기존 DB 적용 전 확인

Supabase SQL Editor에서 먼저 다음을 실행해 구조를 확인합니다.

```sql
select column_name, data_type, is_nullable
from information_schema.columns
where table_schema = 'public' and table_name = 'memos'
order by ordinal_position;

select conname, pg_get_constraintdef(oid)
from pg_constraint
where conrelid = 'public.memos'::regclass;
```

기존 `memos.password_hash`가 있으면 `migration.sql`이 데이터를 `memo_credentials`로 이전하고 공개 테이블에서 해당 컬럼을 제거합니다. 적용 전 메모 ID와 기존 bcrypt 해시가 유효한지 확인하고, 누락 메모는 별도로 확인하십시오.

## Vercel 배포

GitHub 저장소를 Vercel에 연결한 뒤 Project Settings → Environment Variables에 `.env.local.example`의 값을 등록하고 배포합니다. `SUPABASE_SECRET_KEY`, `ADMIN_PASSWORD_HASH`, `ADMIN_SESSION_SECRET`에는 절대 `NEXT_PUBLIC_` 접두사를 붙이지 마세요.

## 보안 구조

- 브라우저는 공개 URL과 Publishable key로 메모 목록만 조회합니다.
- 메모 생성 시 4자리 비밀번호 해시는 서버 API에서 bcrypt로 만듭니다.
- 일반 삭제는 서버에서 해시를 비교한 뒤 Secret key 기반 Supabase 클라이언트로 수행합니다.
- 관리자 인증과 삭제는 HttpOnly 세션 쿠키를 검증하는 서버 API에서만 수행합니다.
- `schema.sql`은 RLS, 비공개 암호 테이블, 그리고 명시적 `GRANT`를 함께 적용합니다.
