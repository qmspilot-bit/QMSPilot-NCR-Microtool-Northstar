-- Northstar multitenant foundation. Applied to Supabase project mcdxriothpcadqcaarui.
-- Auth users receive an isolated organization and membership; qmspilot@gmail.com is assigned the demo tenant.

create extension if not exists pgcrypto;

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(), name text not null, slug text not null unique,
  is_demo boolean not null default false, created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade, email text not null, display_name text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.organization_memberships (
  id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade, role text not null default 'member' check(role in('owner','admin','member','auditor')),
  status text not null default 'active' check(status in('active','invited','disabled')), created_at timestamptz not null default now(), unique(organization_id,user_id)
);
create index if not exists organization_memberships_user_idx on public.organization_memberships(user_id);
create index if not exists organization_memberships_org_idx on public.organization_memberships(organization_id);

create or replace function public.is_org_member(org_id uuid) returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from public.organization_memberships where organization_id=org_id and user_id=auth.uid() and status='active'); $$;
create or replace function public.is_org_admin(org_id uuid) returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from public.organization_memberships where organization_id=org_id and user_id=auth.uid() and status='active' and role in('owner','admin')); $$;

grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.is_org_admin(uuid) to authenticated;

alter table public.organizations enable row level security;
alter table public.profiles enable row level security;
alter table public.organization_memberships enable row level security;

drop policy if exists organizations_select_member on public.organizations;
create policy organizations_select_member on public.organizations for select to authenticated using(public.is_org_member(id));
drop policy if exists profiles_select_self on public.profiles;
create policy profiles_select_self on public.profiles for select to authenticated using(user_id=auth.uid());
drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());
drop policy if exists memberships_select_org on public.organization_memberships;
create policy memberships_select_org on public.organization_memberships for select to authenticated using(user_id=auth.uid() or public.is_org_admin(organization_id));

create or replace function public.handle_new_user_workspace() returns trigger language plpgsql security definer set search_path=public as $$
declare org_id uuid; org_name text; org_slug text; email_domain text;
begin
 insert into public.profiles(user_id,email,display_name) values(new.id,coalesce(new.email,''),coalesce(new.raw_user_meta_data->>'full_name',new.raw_user_meta_data->>'name')) on conflict(user_id) do update set email=excluded.email,updated_at=now();
 if lower(coalesce(new.email,''))='qmspilot@gmail.com' then
   insert into public.organizations(name,slug,is_demo) values('QMSPilot Demo Workspace','qmspilot-demo',true) on conflict(slug) do update set name=excluded.name,is_demo=true,updated_at=now() returning id into org_id;
 else
   email_domain:=nullif(split_part(lower(coalesce(new.email,'')),'@',2),''); org_name:=coalesce(nullif(new.raw_user_meta_data->>'company_name',''),email_domain,'New Company');
   org_slug:=trim(both '-' from regexp_replace(lower(org_name),'[^a-z0-9]+','-','g')); if org_slug='' then org_slug:='company'; end if; org_slug:=left(org_slug,45)||'-'||substr(replace(new.id::text,'-',''),1,8);
   insert into public.organizations(name,slug,is_demo) values(org_name,org_slug,false) returning id into org_id;
 end if;
 insert into public.organization_memberships(organization_id,user_id,role,status) values(org_id,new.id,'owner','active') on conflict(organization_id,user_id) do update set role='owner',status='active'; return new;
end; $$;
drop trigger if exists on_auth_user_created_workspace on auth.users;
create trigger on_auth_user_created_workspace after insert on auth.users for each row execute procedure public.handle_new_user_workspace();

insert into public.organizations(name,slug,is_demo) values('QMSPilot Demo Workspace','qmspilot-demo',true) on conflict(slug) do update set is_demo=true;
alter table public.northstar_records add column if not exists tenant_id uuid references public.organizations(id);
alter table public.northstar_records add column if not exists created_by uuid references auth.users(id);
update public.northstar_records set tenant_id=(select id from public.organizations where slug='qmspilot-demo') where tenant_id is null;
alter table public.northstar_records alter column tenant_id set not null;
drop index if exists public.northstar_records_org_ncr_uq;
create unique index if not exists northstar_records_tenant_ncr_uq on public.northstar_records(tenant_id,ncr_number);
create index if not exists northstar_records_tenant_created_idx on public.northstar_records(tenant_id,created_at desc);
alter table public.northstar_records enable row level security;
drop policy if exists northstar_records_select_tenant on public.northstar_records;
create policy northstar_records_select_tenant on public.northstar_records for select to authenticated using(public.is_org_member(tenant_id));
drop policy if exists northstar_records_insert_tenant on public.northstar_records;
create policy northstar_records_insert_tenant on public.northstar_records for insert to authenticated with check(public.is_org_member(tenant_id) and (created_by is null or created_by=auth.uid()));
drop policy if exists northstar_records_update_tenant on public.northstar_records;
create policy northstar_records_update_tenant on public.northstar_records for update to authenticated using(public.is_org_member(tenant_id)) with check(public.is_org_member(tenant_id));
drop policy if exists northstar_records_delete_tenant on public.northstar_records;
create policy northstar_records_delete_tenant on public.northstar_records for delete to authenticated using(public.is_org_admin(tenant_id));

grant select,update on public.profiles to authenticated;
grant select on public.organizations,public.organization_memberships to authenticated;
grant select,insert,update,delete on public.northstar_records to authenticated;
