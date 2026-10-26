---
title: Lock Down SECURITY DEFINER Functions in Exposed Schemas
impact: CRITICAL
impactDescription: Prevents anon from calling RLS-bypassing functions as a public API endpoint
tags: security-definer, functions, grants, revoke, anon, security
---

## Lock Down SECURITY DEFINER Functions in Exposed Schemas

A `SECURITY DEFINER` function runs as its owner and bypasses RLS. Postgres grants `EXECUTE` to `PUBLIC` on every new function, and in Supabase the default privileges of `public` also grant `EXECUTE` directly to `anon` and `authenticated`. Any such function in an exposed schema is therefore callable through `/rest/v1/rpc` with the public anon key. Never add `SECURITY DEFINER` to make a permission error go away; prefer `SECURITY INVOKER`.

**Incorrect (exposed, callable by anon, no identity check):**

```sql
create function public.assign_lead(p_lead bigint, p_owner uuid)
returns void
language sql
security definer
as $$ update public.leads set owner_id = p_owner where id = p_lead; $$;
-- revoke ... from public alone is not enough: anon still has its own direct grant
```

**Correct (identity checked, pinned search_path, EXECUTE revoked from every API role that should not call it):**

```sql
create function private.assign_lead(p_lead bigint, p_owner uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is null or p_owner is distinct from (select auth.uid()) then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  update public.leads set owner_id = p_owner where id = p_lead;
end;
$$;

revoke execute on function private.assign_lead(bigint, uuid) from public, anon, authenticated;
grant execute on function private.assign_lead(bigint, uuid) to service_role;  -- only if needed
```

Watch the guard shape: `if auth.uid() is not null and ... then raise` never fires for a caller without a session, so it is fail-open for `anon` and for `service_role`. Check the ACL after every `create or replace`:

```sql
select has_function_privilege('anon', 'private.assign_lead(bigint, uuid)', 'execute');  -- expect false
```

Run `supabase db advisors` after changing privileged functions.

Reference: [Database functions: security definer](https://supabase.com/docs/guides/database/functions#security-definer-vs-invoker)
