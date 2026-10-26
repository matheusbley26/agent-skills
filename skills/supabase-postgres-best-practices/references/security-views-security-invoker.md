---
title: Create Views with security_invoker in Exposed Schemas
impact: CRITICAL
impactDescription: Prevents views from silently bypassing RLS of the underlying tables
tags: views, rls, security-invoker, supabase, security
---

## Create Views with security_invoker in Exposed Schemas

By default a view runs with the privileges of its owner (usually `postgres`, which bypasses RLS), so a view in an exposed schema returns every row of the underlying tables to `anon` and `authenticated`.

**Incorrect (view runs as its owner and ignores RLS):**

```sql
create view public.order_summaries as
  select id, user_id, total from public.orders;
-- RLS on orders is enabled, but any authenticated user reads ALL orders through the view
```

**Correct (view runs as the caller, RLS applies):**

```sql
-- Postgres 15+
create view public.order_summaries
  with (security_invoker = true)
  as select id, user_id, total from public.orders;

-- Existing view
alter view public.order_summaries set (security_invoker = true);
```

On Postgres older than 15, revoke access from the API roles or move the view to an unexposed schema:

```sql
revoke all on public.order_summaries from anon, authenticated;
```

Reference: [Securing views](https://supabase.com/docs/guides/database/postgres/row-level-security#views)
