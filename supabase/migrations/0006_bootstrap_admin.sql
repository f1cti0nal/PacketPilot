-- Promote the operator's account to admin. Idempotent; a no-op until that account
-- signs up (the consumer auth UI lands in a later phase). Runs in a migration
-- context (auth.uid() is null), so the profiles privilege guard's carve-out permits
-- the role change. Replace the email if the admin identity changes.
update public.profiles
set role = 'admin'
where email = 'ravi.dholariya@icloud.com';
