---
title: Pair Every UPDATE Policy with a SELECT Policy
impact: HIGH
impactDescription: Avoids updates that silently affect 0 rows
tags: rls, update, select, policies, security
---

## Pair Every UPDATE Policy with a SELECT Policy

An `UPDATE ... WHERE` has to read the rows it targets, and under RLS only rows visible to a SELECT policy can be read. Without a SELECT policy the update matches nothing and returns 0 rows: no error, no change.

**Incorrect (UPDATE policy alone):**

```sql
create policy profiles_update on public.profiles for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

update public.profiles set display_name = 'Ana' where user_id = auth.uid();
-- UPDATE 0: the row is invisible, so nothing matched
```

**Correct (SELECT policy covering the same rows):**

```sql
create policy profiles_select on public.profiles for select
  to authenticated
  using ((select auth.uid()) = user_id);

create policy profiles_update on public.profiles for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
```

When a write returns 0 rows under RLS, check the SELECT policy before debugging the UPDATE policy.

Reference: [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
