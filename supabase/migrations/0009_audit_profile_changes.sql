-- Record admin edits to a user's privileged columns. SECURITY DEFINER so it always
-- writes regardless of the actor's RLS; search_path pinned. actor_id is auth.uid()
-- (the admin), or null for service-role/migration changes.
create or replace function public.audit_profile_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  changes jsonb := '{}'::jsonb;
begin
  if new.role is distinct from old.role then
    changes := changes || jsonb_build_object('role', jsonb_build_object('old', old.role::text, 'new', new.role::text));
  end if;
  if new.plan is distinct from old.plan then
    changes := changes || jsonb_build_object('plan', jsonb_build_object('old', old.plan::text, 'new', new.plan::text));
  end if;
  if new.status is distinct from old.status then
    changes := changes || jsonb_build_object('status', jsonb_build_object('old', old.status::text, 'new', new.status::text));
  end if;
  if changes <> '{}'::jsonb then
    insert into public.audit_log (actor_id, action, target, meta)
    values (auth.uid(), 'profile.update', new.id::text, changes);
  end if;
  return new;
end;
$$;

-- This is a trigger function only — never meant to be called over PostgREST RPC.
-- Trigger execution is unaffected by EXECUTE grants, so revoking keeps it least-privilege
-- (and clears the SECURITY DEFINER "publicly executable" advisory).
revoke execute on function public.audit_profile_change() from public, anon, authenticated;

drop trigger if exists audit_profile_change on public.profiles;
create trigger audit_profile_change
after update on public.profiles
for each row execute function public.audit_profile_change();
