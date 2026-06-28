-- BEFORE INSERT/UPDATE: stamp updated_by from the JWT (a client-set value is untrusted).
create or replace function public.feature_flags_stamp()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.updated_by := auth.uid();
  return new;
end;
$$;
revoke execute on function public.feature_flags_stamp() from public, anon, authenticated;
drop trigger if exists feature_flags_stamp on public.feature_flags;
create trigger feature_flags_stamp
before insert or update on public.feature_flags
for each row execute function public.feature_flags_stamp();

-- AFTER INSERT/UPDATE/DELETE: audit changes to audit_log (mirrors 0009).
create or replace function public.feature_flags_audit()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  changes jsonb := '{}'::jsonb;
begin
  if tg_op = 'DELETE' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'feature_flag.delete', old.key,
      jsonb_build_object('enabled', old.enabled, 'plan_gate', old.plan_gate::text));
    return old;
  elsif tg_op = 'INSERT' then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'feature_flag.create', new.key,
      jsonb_build_object('enabled', new.enabled, 'plan_gate', new.plan_gate::text, 'description', new.description));
    return new;
  else
    if new.enabled is distinct from old.enabled then
      changes := changes || jsonb_build_object('enabled', jsonb_build_object('old', old.enabled, 'new', new.enabled));
    end if;
    if new.plan_gate is distinct from old.plan_gate then
      changes := changes || jsonb_build_object('plan_gate', jsonb_build_object('old', old.plan_gate::text, 'new', new.plan_gate::text));
    end if;
    if new.description is distinct from old.description then
      changes := changes || jsonb_build_object('description', jsonb_build_object('old', old.description, 'new', new.description));
    end if;
    if changes <> '{}'::jsonb then
      insert into public.audit_log (actor_id, action, target, meta)
      values (auth.uid(), 'feature_flag.update', new.key, changes);
    end if;
    return new;
  end if;
end;
$$;
revoke execute on function public.feature_flags_audit() from public, anon, authenticated;
drop trigger if exists feature_flags_audit on public.feature_flags;
create trigger feature_flags_audit
after insert or update or delete on public.feature_flags
for each row execute function public.feature_flags_audit();
