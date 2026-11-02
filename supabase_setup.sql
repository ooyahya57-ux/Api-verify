create table if not exists public.license_keys (
  license_key text primary key,
  is_active boolean not null default true,
  max_devices integer not null default 1 check (max_devices between 1 and 20),
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.license_devices (
  id bigint generated always as identity primary key,
  license_key text not null references public.license_keys(license_key) on delete cascade,
  device_id text not null,
  created_at timestamptz not null default now(),
  unique (license_key, device_id)
);

alter table public.license_keys enable row level security;
alter table public.license_devices enable row level security;

create or replace function public.verify_license(p_key text, p_device text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare k public.license_keys%rowtype;
declare device_count integer;
begin
  if coalesce(trim(p_key),'')='' or coalesce(trim(p_device),'')='' then
    return jsonb_build_object('ok',false,'msg','Missing key or device');
  end if;

  select * into k from public.license_keys
  where license_key=trim(p_key) for update;

  if not found then return jsonb_build_object('ok',false,'msg','Key not found'); end if;
  if not k.is_active then return jsonb_build_object('ok',false,'msg','Key disabled'); end if;
  if k.expires_at is not null and k.expires_at <= now() then
    return jsonb_build_object('ok',false,'msg','Key expired');
  end if;

  if exists(select 1 from public.license_devices
            where license_key=k.license_key and device_id=trim(p_device)) then
    return jsonb_build_object('ok',true,'msg','Key accepted');
  end if;

  select count(*) into device_count from public.license_devices
  where license_key=k.license_key;

  if device_count >= k.max_devices then
    return jsonb_build_object('ok',false,'msg','Device limit reached');
  end if;

  insert into public.license_devices(license_key,device_id)
  values(k.license_key,trim(p_device));

  return jsonb_build_object('ok',true,'msg','Key accepted');
end;
$$;

revoke all on function public.verify_license(text,text) from public, anon, authenticated;
grant execute on function public.verify_license(text,text) to service_role;
