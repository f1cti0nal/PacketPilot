-- Enums
create type public.user_plan as enum ('free', 'pro');
create type public.user_role as enum ('user', 'admin');
create type public.user_status as enum ('active', 'suspended', 'blocked');
create type public.subscription_status as enum (
  'trialing', 'active', 'past_due', 'canceled',
  'incomplete', 'incomplete_expired', 'unpaid', 'paused'
);

-- profiles: 1:1 with auth.users
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text,
  avatar_url text,
  plan public.user_plan not null default 'free',
  role public.user_role not null default 'user',
  status public.user_status not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- subscriptions: Stripe mirror (written by webhooks in Phase 2)
create table public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  stripe_customer_id text,
  stripe_subscription_id text unique,
  price_id text,
  status public.subscription_status not null,
  amount_cents integer,
  currency text not null default 'usd',
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index subscriptions_user_id_idx on public.subscriptions(user_id);

-- feature_flags
create table public.feature_flags (
  key text primary key,
  description text,
  enabled boolean not null default false,
  plan_gate public.user_plan,
  updated_at timestamptz not null default now(),
  updated_by uuid references public.profiles(id)
);

-- app_settings
create table public.app_settings (
  key text primary key,
  value jsonb not null default '{}'::jsonb,
  description text,
  updated_at timestamptz not null default now(),
  updated_by uuid references public.profiles(id)
);

-- analytics_events
create table public.analytics_events (
  id bigint generated always as identity primary key,
  session_id text not null,
  path text not null,
  referrer text,
  user_id uuid references public.profiles(id) on delete set null,
  country text,
  user_agent text,
  created_at timestamptz not null default now()
);
create index analytics_events_created_at_idx on public.analytics_events(created_at);
create index analytics_events_session_idx on public.analytics_events(session_id);

-- audit_log
create table public.audit_log (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id),
  action text not null,
  target text,
  meta jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index audit_log_created_at_idx on public.audit_log(created_at);
