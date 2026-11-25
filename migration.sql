-- 기존 DB 보존 마이그레이션
-- 적용 전제: public.memos 테이블이 이미 존재하며, 기존 컬럼과 데이터가 아래 구조와 호환됩니다.
-- 기존 memos.password_hash를 memo_credentials로 이전한 뒤 공개 컬럼에서 제거합니다.
-- 적용 전에 반드시 확인 SQL로 실제 구조를 확인하세요.

create extension if not exists pgcrypto;

alter table public.memos
  add column if not exists title text,
  add column if not exists content text,
  add column if not exists color text,
  add column if not exists position integer,
  add column if not exists created_at timestamptz,
  add column if not exists updated_at timestamptz;

update public.memos
set title = coalesce(title, ''),
    content = coalesce(content, ''),
    color = coalesce(color, '#fef3c7'),
    position = coalesce(position, 0),
    created_at = coalesce(created_at, now()),
    updated_at = coalesce(updated_at, now());

alter table public.memos
  alter column title set not null,
  alter column content set not null,
  alter column color set not null,
  alter column position set not null,
  alter column created_at set not null,
  alter column updated_at set not null,
  alter column title set default '',
  alter column content set default '',
  alter column color set default '#fef3c7',
  alter column position set default 0,
  alter column created_at set default now(),
  alter column updated_at set default now();

create table if not exists public.memo_credentials (
  memo_id uuid primary key references public.memos(id) on delete cascade,
  password_hash text not null
);

create table if not exists public.admin_sessions (
  token_hash text primary key,
  verification_hash text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists public.abuse_limits (
  key_hash text primary key,
  window_started_at timestamptz not null,
  attempt_count integer not null default 0
);

do $$
begin
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'memos'
      and column_name = 'password_hash'
  ) then
    execute '
      insert into public.memo_credentials (memo_id, password_hash)
      select id, password_hash
      from public.memos
      where password_hash is not null
      on conflict (memo_id) do update
      set password_hash = excluded.password_hash
    ';
  end if;
end;
$$;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conrelid = 'public.memos'::regclass
      and conname = 'memos_title_length_check'
  ) then
    alter table public.memos
      add constraint memos_title_length_check
      check (char_length(title) between 1 and 80);
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conrelid = 'public.memos'::regclass
      and conname = 'memos_content_length_check'
  ) then
    alter table public.memos
      add constraint memos_content_length_check
      check (char_length(content) between 1 and 2000);
  end if;
end;
$$;

-- 마이그레이션 전 누락·중복 검증용 확인 쿼리:
-- select count(*) as memos_without_credentials
-- from public.memos m left join public.memo_credentials c on c.memo_id = m.id
-- where c.memo_id is null;
-- select memo_id, count(*) from public.memo_credentials group by memo_id having count(*) > 1;

alter table public.memos enable row level security;
alter table public.memo_credentials enable row level security;
alter table public.admin_sessions enable row level security;
alter table public.abuse_limits enable row level security;

revoke all on public.memos from anon, authenticated;
revoke all on public.memo_credentials from anon, authenticated;
revoke all on public.admin_sessions from anon, authenticated;
revoke all on public.abuse_limits from anon, authenticated;

grant usage on schema public to anon, authenticated, service_role;
grant select on public.memos to anon, authenticated;
grant all on public.memos to service_role;
grant all on public.memo_credentials to service_role;
grant all on public.admin_sessions to service_role;
grant all on public.abuse_limits to service_role;

drop policy if exists "Public memos are readable" on public.memos;
create policy "Public memos are readable"
on public.memos for select to anon, authenticated using (true);

drop policy if exists "Public memos deny writes" on public.memos;
create policy "Public memos deny writes"
on public.memos for insert to anon, authenticated with check (false);
drop policy if exists "Public memos deny updates" on public.memos;
create policy "Public memos deny updates"
on public.memos for update to anon, authenticated using (false) with check (false);
drop policy if exists "Public memos deny deletes" on public.memos;
create policy "Public memos deny deletes"
on public.memos for delete to anon, authenticated using (false);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists memos_set_updated_at on public.memos;
create trigger memos_set_updated_at
before update on public.memos
for each row
execute function public.set_updated_at();

create or replace function public.create_memo_with_credentials(
  p_title text,
  p_content text,
  p_password_hash text,
  p_color text default '#fef3c7'
)
returns public.memos
language plpgsql
set search_path = public
as $$
declare
  inserted_memo public.memos;
begin
  if char_length(p_title) < 1 or char_length(p_title) > 80 then
    raise exception 'Invalid title length';
  end if;
  if char_length(p_content) < 1 or char_length(p_content) > 2000 then
    raise exception 'Invalid content length';
  end if;
  if char_length(p_password_hash) < 50 then
    raise exception 'Invalid password hash';
  end if;
  if p_color not in ('#fef3c7','#dbeafe','#dcfce7','#fce7f3','#f3e8ff','#fed7aa') then
    raise exception 'Invalid memo color';
  end if;

  insert into public.memos (title, content, color, position, created_at, updated_at)
  values (p_title, p_content, p_color, 0, now(), now())
  returning * into inserted_memo;

  insert into public.memo_credentials (memo_id, password_hash)
  values (inserted_memo.id, p_password_hash);
  return inserted_memo;
end;
$$;

create or replace function public.check_abuse_limit(
  p_key text,
  p_window_seconds integer,
  p_limit integer
)
returns boolean language plpgsql set search_path = public
as $$
declare current_row public.abuse_limits%rowtype;
begin
  select * into current_row from public.abuse_limits
  where key_hash = p_key for update;
  if not found then return true; end if;
  if current_row.window_started_at + make_interval(secs => p_window_seconds) <= now() then
    return true;
  end if;
  return current_row.attempt_count < p_limit;
end;
$$;

create or replace function public.consume_abuse_limit(
  p_key text,
  p_window_seconds integer,
  p_limit integer
)
returns boolean language plpgsql set search_path = public
as $$
declare current_row public.abuse_limits%rowtype;
begin
  select * into current_row from public.abuse_limits
  where key_hash = p_key for update;
  if not found then
    insert into public.abuse_limits (key_hash, window_started_at, attempt_count)
    values (p_key, now(), 1);
    return true;
  end if;
  if current_row.window_started_at + make_interval(secs => p_window_seconds) <= now() then
    update public.abuse_limits set window_started_at = now(), attempt_count = 1
    where key_hash = p_key;
    return true;
  end if;
  if current_row.attempt_count >= p_limit then return false; end if;
  update public.abuse_limits set attempt_count = attempt_count + 1
  where key_hash = p_key;
  return true;
end;
$$;

revoke all on function public.create_memo_with_credentials(text, text, text, text)
from public, anon, authenticated;
grant execute on function public.create_memo_with_credentials(text, text, text, text) to service_role;
revoke all on function public.check_abuse_limit(text, integer, integer)
from public, anon, authenticated;
revoke all on function public.consume_abuse_limit(text, integer, integer)
from public, anon, authenticated;
grant execute on function public.check_abuse_limit(text, integer, integer) to service_role;
grant execute on function public.consume_abuse_limit(text, integer, integer) to service_role;

alter table public.memos drop column if exists password_hash;
