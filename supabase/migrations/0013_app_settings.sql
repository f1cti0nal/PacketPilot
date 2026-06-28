-- BEFORE INSERT/UPDATE: stamp updated_by from the JWT (client value untrusted).
create or replace function public.app_settings_stamp()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.updated_by := auth.uid();
  return new;
end;
$$;
revoke execute on function public.app_settings_stamp() from public, anon, authenticated;
drop trigger if exists app_settings_stamp on public.app_settings;
create trigger app_settings_stamp before insert or update on public.app_settings
for each row execute function public.app_settings_stamp();

-- AFTER INSERT/UPDATE/DELETE: audit to audit_log (mirrors 0012).
create or replace function public.app_settings_audit()
returns trigger language plpgsql security definer set search_path = '' as $$
declare changes jsonb := '{}'::jsonb;
begin
  if tg_op = 'DELETE' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'app_setting.delete', old.key, jsonb_build_object('value', old.value));
    return old;
  elsif tg_op = 'INSERT' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'app_setting.create', new.key, jsonb_build_object('value', new.value, 'description', new.description));
    return new;
  else
    if new.value is distinct from old.value then
      changes := changes || jsonb_build_object('value', jsonb_build_object('old', old.value, 'new', new.value));
    end if;
    if new.description is distinct from old.description then
      changes := changes || jsonb_build_object('description', jsonb_build_object('old', old.description, 'new', new.description));
    end if;
    if changes <> '{}'::jsonb then
      insert into public.audit_log (actor_id, action, target, meta)
      values (auth.uid(), 'app_setting.update', new.key, changes);
    end if;
    return new;
  end if;
end;
$$;
revoke execute on function public.app_settings_audit() from public, anon, authenticated;
drop trigger if exists app_settings_audit on public.app_settings;
create trigger app_settings_audit after insert or update or delete on public.app_settings
for each row execute function public.app_settings_audit();

-- Narrow PUBLIC read: only whitelisted, non-secret keys (never the whole admin table).
create or replace function public.get_public_settings()
returns jsonb language sql stable security definer set search_path = '' as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
  from public.app_settings
  where key in ('announcement_banner', 'support_contact_email', 'pro_plan_price_display');
$$;
grant execute on function public.get_public_settings() to anon, authenticated;

-- Seed the banner key (off by default; empty text => nothing shown).
insert into public.app_settings (key, value, description) values
  ('announcement_banner', '{"text":"","severity":"info","dismissible":true}'::jsonb, 'Site-wide announcement banner')
on conflict (key) do nothing;
