---
title: Treat TO authenticated as Authentication, Not Authorization
impact: CRITICAL
impactDescription: Prevents BOLA/IDOR where any signed-in user reads or writes every row
tags: rls, authorization, bola, idor, security
---

## Treat TO authenticated as Authentication, Not Authorization

`TO authenticated` only filters by Postgres role: it says the caller is signed in, not which rows belong to them. Anonymous sign-ins also get the `authenticated` role. Every policy needs a row predicate that ties the row to the caller.

**Incorrect (role check only):**

```sql
create policy invoices_select on public.invoices for select
  to authenticated
  using (true);
-- Every signed-in user (anonymous sign-ins included) reads every invoice
```

**Correct (role plus ownership or tenancy predicate):**

```sql
create policy invoices_select on public.invoices for select
  to authenticated
  using ((select auth.uid()) = customer_id);

-- Multi-tenant: membership lookup, indexed
create policy invoices_select_team on public.invoices for select
  to authenticated
  using (team_id in (select team_id from public.team_members
                      where user_id = (select auth.uid())));
```

Reference: [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
