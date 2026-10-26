---
title: Grant INSERT, SELECT and UPDATE for Storage Upsert
impact: MEDIUM
impactDescription: Avoids file replacement (upsert) failing while new uploads succeed
tags: storage, rls, upsert, policies, security
---

## Grant INSERT, SELECT and UPDATE for Storage Upsert

Storage access is RLS on `storage.objects`. A plain upload needs only INSERT, but an upload with `upsert: true` that replaces an existing object also needs SELECT (to find it) and UPDATE (to overwrite it). With INSERT alone, first uploads work and replacements fail.

**Incorrect (INSERT only):**

```sql
create policy avatars_insert on storage.objects for insert
  to authenticated
  with check (bucket_id = 'avatars'
              and (storage.foldername(name))[1] = (select auth.uid())::text);
-- upload(path, file, { upsert: true }) fails once the file exists
```

**Correct (all three, same path rule):**

```sql
create policy avatars_insert on storage.objects for insert
  to authenticated
  with check (bucket_id = 'avatars'
              and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy avatars_select on storage.objects for select
  to authenticated
  using (bucket_id = 'avatars'
         and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy avatars_update on storage.objects for update
  to authenticated
  using (bucket_id = 'avatars'
         and (storage.foldername(name))[1] = (select auth.uid())::text)
  with check (bucket_id = 'avatars'
              and (storage.foldername(name))[1] = (select auth.uid())::text);
```

Reference: [Storage access control](https://supabase.com/docs/guides/storage/security/access-control)
