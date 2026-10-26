---
title: Give UPDATE Policies Both USING and WITH CHECK
impact: CRITICAL
impactDescription: Prevents users from reassigning rows to other owners or tenants
tags: rls, update, with-check, policies, security
---

## Give UPDATE Policies Both USING and WITH CHECK

`USING` decides which existing rows a user may update; `WITH CHECK` decides what the row may look like afterwards. With `USING` alone, a user can update their own row and move it to another owner or tenant. A permissive `WITH CHECK (true)` or `WITH CHECK (auth.uid() is not null)` has the same hole, since any signed-in JWT passes it.

**Incorrect (no constraint on the new row):**

```sql
create policy documents_update on public.documents for update
  to authenticated
  using ((select auth.uid()) = owner_id);

-- Allowed: hands the row to someone else
update public.documents set owner_id = '<other-user-uuid>' where id = 42;
```

**Correct (old and new row both checked):**

```sql
create policy documents_update on public.documents for update
  to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
```

Columns that grant power (role, tenant, active flag) need a trigger or column-level privileges on top of `WITH CHECK`, because the policy sees the whole row, not which column changed.

Reference: [Row Level Security policies](https://www.postgresql.org/docs/current/sql-createpolicy.html)
