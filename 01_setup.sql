-- =====================================================================
--  INFORMATIKA TEST TIZIMI  -  1-QADAM: jadvallar, xavfsizlik, funksiyalar
--  Supabase -> SQL Editor -> New query -> shu faylni to'liq qo'yib RUN bosing.
--  Qayta ishga tushirish xavfsiz: mavjud ma'lumotlar o'chmaydi.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- Ichki (tashqaridan ko'rinmaydigan) funksiyalar uchun alohida sxema
create schema if not exists app_private;
revoke all on schema app_private from public, anon, authenticated;

-- ---------------------------------------------------------------------
--  JADVALLAR
-- ---------------------------------------------------------------------
create table if not exists public.app_users (
  id              uuid primary key default gen_random_uuid(),
  username        text not null unique,
  password_hash   text not null,
  role            text not null check (role in ('student','teacher')),
  full_name       text not null,
  grade           int,
  class_name      text,
  grp             int,
  failed_attempts int  not null default 0,
  locked_until    timestamptz,
  created_at      timestamptz not null default now()
);

create table if not exists public.app_tests (
  grade            int primary key,
  is_open          boolean not null default true,
  duration_minutes int not null default 0          -- 0 = vaqt cheklovi yo'q
);

create table if not exists public.app_questions (
  id       serial primary key,
  grade    int  not null,
  num      int  not null,
  question text not null,
  options  jsonb not null,
  correct  int  not null,                          -- to'g'ri variant tartibi (0 dan)
  unique (grade, num)
);

create table if not exists public.app_attempts (
  id           bigserial primary key,
  user_id      uuid not null references public.app_users(id) on delete cascade,
  started_at   timestamptz not null default now(),
  submitted_at timestamptz,
  score        int,
  total        int,
  answers      jsonb,
  late         boolean not null default false,
  superseded   boolean not null default false      -- o'qituvchi qayta ochgan eski urinish
);
create unique index if not exists app_one_active_attempt
  on public.app_attempts (user_id) where not superseded;

create table if not exists public.app_sessions (
  token      text primary key,
  user_id    uuid not null references public.app_users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

-- Jadvallar butunlay yopiq: brauzer ularga to'g'ridan-to'g'ri kira olmaydi.
alter table public.app_users     enable row level security;
alter table public.app_tests     enable row level security;
alter table public.app_questions enable row level security;
alter table public.app_attempts  enable row level security;
alter table public.app_sessions  enable row level security;
revoke all on public.app_users, public.app_tests, public.app_questions,
              public.app_attempts, public.app_sessions from public, anon, authenticated;
revoke all on all sequences in schema public from public, anon, authenticated;

-- ---------------------------------------------------------------------
--  ICHKI YORDAMCHI FUNKSIYALAR
-- ---------------------------------------------------------------------
create or replace function app_private.auth(p_token text, p_role text default null)
returns public.app_users
language plpgsql security definer set search_path = public, extensions as $$
declare u public.app_users;
begin
  select au.* into u
    from public.app_sessions s join public.app_users au on au.id = s.user_id
   where s.token = p_token and s.expires_at > now();
  if not found then raise exception 'not_authenticated'; end if;
  if p_role is not null and u.role <> p_role then raise exception 'forbidden'; end if;
  return u;
end $$;

create or replace function app_private.review(p_attempt bigint)
returns jsonb
language sql stable security definer set search_path = public, extensions as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'num', q.num, 'question', q.question, 'options', q.options,
           'chosen', (a.answers ->> q.id::text)::int,
           'correct', q.correct,
           'is_correct', coalesce((a.answers ->> q.id::text)::int = q.correct, false)
         ) order by q.num), '[]'::jsonb)
    from public.app_attempts a
    join public.app_users u on u.id = a.user_id
    join public.app_questions q on q.grade = u.grade
   where a.id = p_attempt;
$$;

-- ---------------------------------------------------------------------
--  OMMAVIY FUNKSIYALAR (sayt shularni chaqiradi)
-- ---------------------------------------------------------------------
create or replace function public.app_ping()
returns text language sql security definer set search_path = public as $$ select 'ok'::text $$;

-- Kirish. Xato bo'lsa istisno o'rniga {ok:false} qaytaradi (urinishlar hisobi saqlansin deb).
create or replace function public.app_login(p_username text, p_password text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.app_users; tok text; n int;
begin
  delete from public.app_sessions where expires_at < now();
  select * into u from public.app_users where username = lower(trim(coalesce(p_username,'')));
  if not found then
    perform pg_sleep(0.3);
    return jsonb_build_object('ok', false, 'error', 'invalid_credentials');
  end if;
  if u.locked_until is not null and u.locked_until > now() then
    return jsonb_build_object('ok', false, 'error', 'locked',
             'minutes', greatest(1, ceil(extract(epoch from (u.locked_until - now())) / 60)::int));
  end if;
  if u.password_hash <> crypt(coalesce(p_password,''), u.password_hash) then
    n := u.failed_attempts + 1;
    update public.app_users
       set failed_attempts = case when n >= 5 then 0 else n end,
           locked_until    = case when n >= 5 then now() + interval '10 minutes' else null end
     where id = u.id;
    return jsonb_build_object('ok', false, 'error', 'invalid_credentials');
  end if;
  update public.app_users set failed_attempts = 0, locked_until = null where id = u.id;
  tok := encode(gen_random_bytes(32), 'hex');
  insert into public.app_sessions(token, user_id, expires_at) values (tok, u.id, now() + interval '12 hours');
  return jsonb_build_object('ok', true, 'token', tok, 'role', u.role, 'full_name', u.full_name,
           'username', u.username, 'grade', u.grade, 'class_name', u.class_name, 'grp', u.grp);
end $$;

create or replace function public.app_logout(p_token text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  delete from public.app_sessions where token = p_token;
  return true;
end $$;

-- O'quvchining bosh sahifasi uchun holat
create or replace function public.app_me(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.app_users; t public.app_tests; a public.app_attempts; nq int;
begin
  u := app_private.auth(p_token);
  if u.role = 'teacher' then
    return jsonb_build_object('role','teacher','full_name',u.full_name,'username',u.username);
  end if;
  select * into t from public.app_tests where grade = u.grade;
  select count(*) into nq from public.app_questions where grade = u.grade;
  select * into a from public.app_attempts where user_id = u.id and not superseded;
  return jsonb_build_object(
    'role','student','full_name',u.full_name,'username',u.username,
    'grade',u.grade,'class_name',u.class_name,'grp',u.grp,
    'test', jsonb_build_object('is_open', coalesce(t.is_open,false),
                               'duration_minutes', coalesce(t.duration_minutes,0), 'questions', nq),
    'attempt', case when a.id is null then null else jsonb_build_object(
        'status', case when a.submitted_at is null then 'in_progress' else 'submitted' end,
        'started_at', a.started_at, 'submitted_at', a.submitted_at,
        'score', a.score, 'total', a.total, 'late', a.late) end);
end $$;

-- Testni boshlash (yoki yarim qolgan testni davom ettirish). To'g'ri javoblar YUBORILMAYDI.
create or replace function public.app_start_test(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.app_users; t public.app_tests; a public.app_attempts;
begin
  u := app_private.auth(p_token, 'student');
  select * into t from public.app_tests where grade = u.grade;
  select * into a from public.app_attempts where user_id = u.id and not superseded;
  if found and a.submitted_at is not null then raise exception 'already_submitted'; end if;
  if not found then
    if not coalesce(t.is_open,false) then raise exception 'test_closed'; end if;
    insert into public.app_attempts(user_id, total)
      values (u.id, (select count(*) from public.app_questions where grade = u.grade))
      returning * into a;
  end if;
  return jsonb_build_object(
    'attempt_id', a.id, 'started_at', a.started_at, 'server_now', now(),
    'duration_minutes', coalesce(t.duration_minutes,0),
    'questions', (select coalesce(jsonb_agg(jsonb_build_object(
                    'id', q.id, 'num', q.num, 'question', q.question, 'options', q.options)
                    order by q.num), '[]'::jsonb)
                  from public.app_questions q where q.grade = u.grade));
end $$;

-- Javoblarni topshirish. Ball serverda hisoblanadi.
-- p_answers: {"<savol id>": <variant tartibi 0 dan>, ...}
create or replace function public.app_submit_test(p_token text, p_answers jsonb)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.app_users; t public.app_tests; a public.app_attempts;
        v_score int; v_total int; v_ans jsonb; v_late boolean;
begin
  u := app_private.auth(p_token, 'student');
  if jsonb_typeof(p_answers) is distinct from 'object' then raise exception 'bad_request'; end if;
  select * into a from public.app_attempts where user_id = u.id and not superseded and submitted_at is null;
  if not found then raise exception 'no_active_attempt'; end if;
  select * into t from public.app_tests where grade = u.grade;
  v_late := coalesce(t.duration_minutes,0) > 0
            and now() > a.started_at + make_interval(mins => t.duration_minutes + 2);
  with c as (
    select q.id, q.correct,
           case when jsonb_typeof(p_answers -> q.id::text) = 'number'
                then (p_answers ->> q.id::text)::numeric::int end as ch
      from public.app_questions q where q.grade = u.grade)
  select (count(*) filter (where ch = correct))::int, count(*)::int,
         coalesce(jsonb_object_agg(id::text, ch) filter (where ch is not null), '{}'::jsonb)
    into v_score, v_total, v_ans from c;
  update public.app_attempts
     set submitted_at = now(), score = v_score, total = v_total, answers = v_ans, late = v_late
   where id = a.id;
  return jsonb_build_object('score', v_score, 'total', v_total);
end $$;

-- O'quvchi o'z natijasi va xatolar tahlili
create or replace function public.app_get_result(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u public.app_users; a public.app_attempts;
begin
  u := app_private.auth(p_token, 'student');
  select * into a from public.app_attempts where user_id = u.id and not superseded and submitted_at is not null;
  if not found then raise exception 'no_result'; end if;
  return jsonb_build_object('score', a.score, 'total', a.total, 'submitted_at', a.submitted_at,
                            'late', a.late, 'review', app_private.review(a.id));
end $$;

-- ---------------------------------------------------------------------
--  O'QITUVCHI FUNKSIYALARI
-- ---------------------------------------------------------------------
create or replace function public.t_results(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform app_private.auth(p_token, 'teacher');
  return coalesce((
    select jsonb_agg(x.j order by x.grade, x.class_name, x.grp nulls first, x.full_name)
      from (
        select u.grade, u.class_name, u.grp, u.full_name,
               jsonb_build_object(
                 'id', u.id, 'full_name', u.full_name, 'username', u.username,
                 'grade', u.grade, 'class_name', u.class_name, 'grp', u.grp,
                 'status', case when a.id is null then 'not_started'
                                when a.submitted_at is null then 'in_progress'
                                else 'submitted' end,
                 'score', a.score, 'total', a.total, 'submitted_at', a.submitted_at,
                 'late', coalesce(a.late, false),
                 'attempts', (select count(*) from public.app_attempts z where z.user_id = u.id)
               ) as j
          from public.app_users u
          left join public.app_attempts a on a.user_id = u.id and not a.superseded
         where u.role = 'student') x), '[]'::jsonb);
end $$;

create or replace function public.t_student_review(p_token text, p_user uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare a public.app_attempts; u public.app_users;
begin
  perform app_private.auth(p_token, 'teacher');
  select * into u from public.app_users where id = p_user and role = 'student';
  if not found then raise exception 'not_found'; end if;
  select * into a from public.app_attempts where user_id = p_user and not superseded and submitted_at is not null;
  if not found then raise exception 'no_result'; end if;
  return jsonb_build_object('full_name', u.full_name, 'class_name', u.class_name,
           'score', a.score, 'total', a.total, 'submitted_at', a.submitted_at, 'late', a.late,
           'review', app_private.review(a.id));
end $$;

-- Testni qayta ochish: eski urinish tarixda qoladi, o'quvchi qaytadan topshira oladi
create or replace function public.t_reopen(p_token text, p_user uuid)
returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform app_private.auth(p_token, 'teacher');
  update public.app_attempts set superseded = true where user_id = p_user and not superseded;
  return true;
end $$;

create or replace function public.t_reset_password(p_token text, p_user uuid, p_new text)
returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform app_private.auth(p_token, 'teacher');
  if length(coalesce(p_new,'')) < 4 then raise exception 'password_too_short'; end if;
  update public.app_users
     set password_hash = crypt(p_new, gen_salt('bf', 10)), failed_attempts = 0, locked_until = null
   where id = p_user and role = 'student';
  if not found then raise exception 'not_found'; end if;
  delete from public.app_sessions where user_id = p_user;
  return true;
end $$;

create or replace function public.t_get_tests(p_token text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform app_private.auth(p_token, 'teacher');
  return coalesce((select jsonb_agg(jsonb_build_object(
            'grade', t.grade, 'is_open', t.is_open, 'duration_minutes', t.duration_minutes,
            'questions', (select count(*) from public.app_questions q where q.grade = t.grade))
            order by t.grade) from public.app_tests t), '[]'::jsonb);
end $$;

create or replace function public.t_set_test(p_token text, p_grade int, p_is_open boolean, p_duration int)
returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform app_private.auth(p_token, 'teacher');
  if p_duration < 0 or p_duration > 600 then raise exception 'bad_request'; end if;
  update public.app_tests set is_open = p_is_open, duration_minutes = p_duration where grade = p_grade;
  if not found then raise exception 'not_found'; end if;
  return true;
end $$;

create or replace function public.app_change_password(p_token text, p_old text, p_new text)
returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare u public.app_users;
begin
  u := app_private.auth(p_token, 'teacher');
  if u.password_hash <> crypt(coalesce(p_old,''), u.password_hash) then raise exception 'wrong_password'; end if;
  if length(coalesce(p_new,'')) < 8 then raise exception 'password_too_short'; end if;
  update public.app_users set password_hash = crypt(p_new, gen_salt('bf', 10)) where id = u.id;
  return true;
end $$;

-- ---------------------------------------------------------------------
--  RUXSATLAR: faqat shu funksiyalarni brauzer chaqira oladi
-- ---------------------------------------------------------------------
revoke all on function app_private.auth(text, text)   from public, anon, authenticated;
revoke all on function app_private.review(bigint)     from public, anon, authenticated;

revoke all on function public.app_ping()                              from public;
revoke all on function public.app_login(text, text)                   from public;
revoke all on function public.app_logout(text)                        from public;
revoke all on function public.app_me(text)                            from public;
revoke all on function public.app_start_test(text)                    from public;
revoke all on function public.app_submit_test(text, jsonb)            from public;
revoke all on function public.app_get_result(text)                    from public;
revoke all on function public.t_results(text)                         from public;
revoke all on function public.t_student_review(text, uuid)            from public;
revoke all on function public.t_reopen(text, uuid)                    from public;
revoke all on function public.t_reset_password(text, uuid, text)      from public;
revoke all on function public.t_get_tests(text)                       from public;
revoke all on function public.t_set_test(text, int, boolean, int)     from public;
revoke all on function public.app_change_password(text, text, text)   from public;

grant execute on function public.app_ping()                              to anon, authenticated;
grant execute on function public.app_login(text, text)                   to anon, authenticated;
grant execute on function public.app_logout(text)                        to anon, authenticated;
grant execute on function public.app_me(text)                            to anon, authenticated;
grant execute on function public.app_start_test(text)                    to anon, authenticated;
grant execute on function public.app_submit_test(text, jsonb)            to anon, authenticated;
grant execute on function public.app_get_result(text)                    to anon, authenticated;
grant execute on function public.t_results(text)                         to anon, authenticated;
grant execute on function public.t_student_review(text, uuid)            to anon, authenticated;
grant execute on function public.t_reopen(text, uuid)                    to anon, authenticated;
grant execute on function public.t_reset_password(text, uuid, text)      to anon, authenticated;
grant execute on function public.t_get_tests(text)                       to anon, authenticated;
grant execute on function public.t_set_test(text, int, boolean, int)     to anon, authenticated;
grant execute on function public.app_change_password(text, text, text)   to anon, authenticated;
