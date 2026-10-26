---
title: Use the TO Clause Instead of auth.role()
impact: HIGH
impactDescription: Removes a deprecated check that passes for anonymous sign-ins
tags: rls, auth-role, deprecated, anonymous-sign-in, security
---

## Use the TO Clause Instead of auth.role()

Supabase deprecated `auth.role()` in policies. Besides the deprecation, `auth.role() = 'authenticated'` is also true for anonymous sign-ins, which carry the `authenticated` role, so the check does not mean "a real user". Name the role in `TO` and put the row rule in `USING`.

**Incorrect (deprecated, evaluated per row):**

```sql
create policy posts_select on public.posts for select
  using (auth.role() = 'authenticated');
```

**Correct (role in TO, row rule in USING):**

```sql
create policy posts_select on public.posts for select
  to authenticated
  using ((select auth.uid()) = author_id);
```

If anonymous users must be excluded, check the `is_anonymous` claim:

```sql
using (
  (select auth.uid()) = author_id
  and coalesce(((select auth.jwt()) ->> 'is_anonymous')::boolean, false) = false
);
```

Reference: [Anonymous sign-ins and RLS](https://supabase.com/docs/guides/auth/auth-anonymous)
