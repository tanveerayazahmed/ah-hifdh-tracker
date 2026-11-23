create extension if not exists pgcrypto with schema extensions;

create table boys(
  id uuid primary key default gen_random_uuid(),
  name text not null,
  code text not null unique,
  pin_hash text not null,
  fails int not null default 0,
  locked_until timestamptz,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create table entries(
  id bigint generated always as identity primary key,
  boy_id uuid not null references boys(id) on delete cascade,
  kind text not null check (kind in ('new','revision','prior')),
  surah int not null check (surah between 1 and 114),
  from_ayah int not null check (from_ayah >= 1),
  to_ayah int not null,
  mistakes int not null default 0 check (mistakes >= 0),
  session_date date not null default (now() at time zone 'Asia/Kuwait')::date,
  source text not null check (source in ('parent','teacher')),
  status text not null default 'pending' check (status in ('pending','verified','rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz,
  check (to_ayah >= from_ayah)
);
create index on entries(boy_id);
create table settings(k text primary key, v text);
insert into settings values ('goal_label','Class goal'),('goal_target','2000'),('goal_start',to_char(now(),'YYYY-MM-DD'));

alter table boys enable row level security;
alter table entries enable row level security;
alter table settings enable row level security;
revoke all on boys, entries, settings from anon, authenticated;

create or replace function _ayah_count(s int) returns int language sql immutable set search_path = public as $$
  select (array[7,286,200,176,120,165,206,75,129,109,123,111,43,52,99,128,111,110,98,135,112,78,118,64,77,227,93,88,69,60,34,30,73,54,45,83,182,88,75,85,54,53,89,59,37,35,38,29,18,45,60,49,62,55,78,96,29,22,24,13,14,11,11,18,12,12,30,52,52,44,28,28,20,56,40,31,50,40,46,42,29,19,36,25,22,17,19,26,30,20,15,21,11,8,8,19,5,8,8,11,11,8,3,9,5,4,7,3,6,3,5,4,5,6])[s]
$$;

create or replace function _valid(s int, f int, t int) returns void language plpgsql set search_path = public as $$
begin
  if s < 1 or s > 114 or f < 1 or t < f or t > _ayah_count(s) then
    raise exception 'Invalid surah/ayah range';
  end if;
end $$;

create or replace function _parent(p_code text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare b boys;
begin
  select * into b from boys where code = upper(trim(p_code)) and active;
  if b.id is null then return json_build_object('err','Wrong code or PIN'); end if;
  if b.locked_until is not null and b.locked_until > now() then
    return json_build_object('err','Too many wrong tries. Try again in 15 minutes.');
  end if;
  if b.pin_hash <> crypt(p_pin, b.pin_hash) then
    if b.fails + 1 >= 5 then
      update boys set fails = 0, locked_until = now() + interval '15 minutes' where id = b.id;
    else
      update boys set fails = b.fails + 1 where id = b.id;
    end if;
    return json_build_object('err','Wrong code or PIN');
  end if;
  if b.fails > 0 then update boys set fails = 0 where id = b.id; end if;
  return json_build_object('id', b.id);
end $$;

create or replace function _teacher(p_pin text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare h text; lk timestamptz; f int;
begin
  select v into h from settings where k = 'teacher_pin';
  if h is null then return 'Teacher PIN not set up'; end if;
  select v::timestamptz into lk from settings where k = 'teacher_locked';
  if lk is not null and lk > now() then return 'Too many wrong tries. Try again in 15 minutes.'; end if;
  if h <> crypt(coalesce(p_pin,''), h) then
    select coalesce(v::int,0) + 1 into f from settings where k = 'teacher_fails';
    f := coalesce(f, 1);
    if f >= 5 then
      insert into settings values ('teacher_locked', (now() + interval '15 minutes')::text) on conflict (k) do update set v = excluded.v;
      f := 0;
    end if;
    insert into settings values ('teacher_fails', f::text) on conflict (k) do update set v = excluded.v;
    return 'Wrong PIN';
  end if;
  insert into settings values ('teacher_fails','0') on conflict (k) do update set v = '0';
  return null;
end $$;

create or replace function _class() returns json language sql security definer set search_path = public as $$
  select json_build_object(
    'label', (select v from settings where k='goal_label'),
    'target', (select v::int from settings where k='goal_target'),
    'start', (select v from settings where k='goal_start'),
    'done', coalesce((select sum(to_ayah - from_ayah + 1) from entries e join boys b on b.id = e.boy_id
        where b.active and e.kind = 'new' and e.status = 'verified'
        and e.session_date >= (select v::date from settings where k='goal_start')),0))
$$;

create or replace function _entries(p_boy uuid) returns json language sql security definer set search_path = public as $$
  select coalesce(json_agg(json_build_object('id',id,'kind',kind,'surah',surah,'from',from_ayah,'to',to_ayah,
    'mistakes',mistakes,'date',session_date,'source',source,'status',status) order by session_date, id), '[]'::json)
  from entries where boy_id = p_boy and status <> 'rejected'
$$;

-- PARENT
create or replace function parent_get(p_code text, p_pin text) returns json
language plpgsql security definer set search_path = public as $$
declare pa json; bid uuid;
begin
  pa := _parent(p_code, p_pin); if pa->>'err' is not null then return json_build_object('error', pa->>'err'); end if; bid := (pa->>'id')::uuid;
  return json_build_object('boy', (select json_build_object('id',id,'name',name,'code',code) from boys where id = bid),
    'entries', _entries(bid), 'class', _class());
end $$;

create or replace function parent_add(p_code text, p_pin text, p_kind text, p_surah int, p_from int, p_to int, p_mistakes int, p_date date)
returns json language plpgsql security definer set search_path = public as $$
declare pa json; bid uuid;
begin
  pa := _parent(p_code, p_pin); if pa->>'err' is not null then return json_build_object('error', pa->>'err'); end if; bid := (pa->>'id')::uuid;
  if p_kind not in ('new','revision') then raise exception 'Invalid type'; end if;
  perform _valid(p_surah, p_from, p_to);
  if p_date > (now() at time zone 'Asia/Kuwait')::date or p_date < (now() at time zone 'Asia/Kuwait')::date - 14 then
    raise exception 'Date must be within the last 14 days';
  end if;
  insert into entries(boy_id, kind, surah, from_ayah, to_ayah, mistakes, session_date, source)
    values (bid, p_kind, p_surah, p_from, p_to, greatest(coalesce(p_mistakes,0),0), p_date, 'parent');
  return parent_get(p_code, p_pin);
end $$;

create or replace function parent_delete(p_code text, p_pin text, p_id bigint) returns json
language plpgsql security definer set search_path = public as $$
declare pa json; bid uuid;
begin
  pa := _parent(p_code, p_pin); if pa->>'err' is not null then return json_build_object('error', pa->>'err'); end if; bid := (pa->>'id')::uuid;
  delete from entries where id = p_id and boy_id = bid and status = 'pending';
  return parent_get(p_code, p_pin);
end $$;

-- TEACHER
create or replace function teacher_status() returns json language sql security definer set search_path = public as $$
  select json_build_object('setup', exists(select 1 from settings where k = 'teacher_pin'))
$$;

create or replace function teacher_setup(p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  if exists(select 1 from settings where k = 'teacher_pin') then raise exception 'Already set up'; end if;
  if length(p_pin) < 6 then raise exception 'PIN must be at least 6 digits'; end if;
  insert into settings values ('teacher_pin', crypt(p_pin, gen_salt('bf')));
  return json_build_object('ok', true);
end $$;

create or replace function teacher_get(p_pin text) returns json
language plpgsql security definer set search_path = public as $$
declare ae text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  return json_build_object(
    'boys', coalesce((select json_agg(json_build_object('id',b.id,'name',b.name,'code',b.code,'active',b.active,
        'entries', _entries(b.id)) order by b.name) from boys b), '[]'::json),
    'class', _class());
end $$;

create or replace function _new_code() returns text language plpgsql set search_path = public as $$
declare c text;
begin
  loop
    c := 'AHB' || lpad((floor(random()*900)+100)::int::text, 3, '0');
    exit when not exists(select 1 from boys where code = c);
  end loop;
  return c;
end $$;

create or replace function teacher_add_boy(p_pin text, p_name text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare ae text; c text; pin text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  if length(trim(coalesce(p_name,''))) < 2 then raise exception 'Enter a name'; end if;
  c := _new_code();
  pin := lpad((floor(random()*10000))::int::text, 4, '0');
  insert into boys(name, code, pin_hash) values (trim(p_name), c, crypt(pin, gen_salt('bf')));
  return json_build_object('code', c, 'pin', pin);
end $$;

create or replace function teacher_reset_pin(p_pin text, p_boy uuid) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare ae text; pin text; c text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  pin := lpad((floor(random()*10000))::int::text, 4, '0');
  update boys set pin_hash = crypt(pin, gen_salt('bf')), fails = 0, locked_until = null where id = p_boy returning code into c;
  return json_build_object('code', c, 'pin', pin);
end $$;

create or replace function teacher_update_boy(p_pin text, p_boy uuid, p_name text, p_active boolean) returns json
language plpgsql security definer set search_path = public as $$
declare ae text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  update boys set name = coalesce(nullif(trim(p_name),''), name), active = coalesce(p_active, active) where id = p_boy;
  return teacher_get(p_pin);
end $$;

create or replace function teacher_review(p_pin text, p_id bigint, p_status text, p_mistakes int) returns json
language plpgsql security definer set search_path = public as $$
declare ae text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  if p_status not in ('verified','rejected') then raise exception 'Invalid status'; end if;
  update entries set status = p_status, mistakes = coalesce(p_mistakes, mistakes), reviewed_at = now() where id = p_id;
  return teacher_get(p_pin);
end $$;

create or replace function teacher_add(p_pin text, p_boy uuid, p_kind text, p_surah int, p_from int, p_to int, p_mistakes int, p_date date)
returns json language plpgsql security definer set search_path = public as $$
declare ae text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  if p_kind not in ('new','revision','prior') then raise exception 'Invalid type'; end if;
  perform _valid(p_surah, p_from, p_to);
  insert into entries(boy_id, kind, surah, from_ayah, to_ayah, mistakes, session_date, source, status, reviewed_at)
    values (p_boy, p_kind, p_surah, p_from, p_to, greatest(coalesce(p_mistakes,0),0),
            coalesce(p_date, (now() at time zone 'Asia/Kuwait')::date), 'teacher', 'verified', now());
  return teacher_get(p_pin);
end $$;

create or replace function teacher_add_prior(p_pin text, p_boy uuid, p_from_surah int, p_to_surah int) returns json
language plpgsql security definer set search_path = public as $$
declare ae text; s int;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  if p_from_surah < 1 or p_to_surah > 114 or p_to_surah < p_from_surah then raise exception 'Invalid surah range'; end if;
  for s in p_from_surah..p_to_surah loop
    insert into entries(boy_id, kind, surah, from_ayah, to_ayah, mistakes, source, status, reviewed_at)
      values (p_boy, 'prior', s, 1, _ayah_count(s), 0, 'teacher', 'verified', now());
  end loop;
  return teacher_get(p_pin);
end $$;

create or replace function teacher_delete(p_pin text, p_id bigint) returns json
language plpgsql security definer set search_path = public as $$
declare ae text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  delete from entries where id = p_id;
  return teacher_get(p_pin);
end $$;

create or replace function teacher_set_goal(p_pin text, p_label text, p_target int, p_start date) returns json
language plpgsql security definer set search_path = public as $$
declare ae text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  update settings set v = coalesce(nullif(trim(p_label),''), v) where k = 'goal_label';
  update settings set v = greatest(coalesce(p_target, 1), 1)::text where k = 'goal_target';
  update settings set v = coalesce(p_start::text, v) where k = 'goal_start';
  return teacher_get(p_pin);
end $$;

create or replace function teacher_change_pin(p_pin text, p_new text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare ae text;
begin
  ae := _teacher(p_pin); if ae is not null then return json_build_object('error', ae); end if;
  if length(p_new) < 6 then raise exception 'PIN must be at least 6 digits'; end if;
  update settings set v = crypt(p_new, gen_salt('bf')) where k = 'teacher_pin';
  return json_build_object('ok', true);
end $$;

-- lock down: only the public RPCs are callable
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function parent_get(text,text), parent_add(text,text,text,int,int,int,int,date), parent_delete(text,text,bigint),
  teacher_status(), teacher_setup(text), teacher_get(text), teacher_add_boy(text,text), teacher_reset_pin(text,uuid),
  teacher_update_boy(text,uuid,text,boolean), teacher_review(text,bigint,text,int),
  teacher_add(text,uuid,text,int,int,int,int,date), teacher_add_prior(text,uuid,int,int), teacher_delete(text,bigint),
  teacher_set_goal(text,text,int,date), teacher_change_pin(text,text) to anon;
