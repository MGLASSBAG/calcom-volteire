-- Cal.com authenticates requests in its server and connects as postgres.
-- Its application tables must not be reachable with Supabase public API keys.
-- Keep this in Prisma history so deployments and restored databases retain it.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

DO $migration$
DECLARE
  relation record;
  api_role text;
BEGIN
  -- Ordinary PostgreSQL installations do not have Supabase API roles.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon')
     AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    RAISE NOTICE 'No Supabase API roles; skipping Supabase access hardening';
    RETURN;
  END IF;

  -- Fail closed if this is pointed at a different application or access model.
  IF to_regclass('public."Booking"') IS NULL
     OR to_regclass('public."EventType"') IS NULL
     OR to_regclass('public.users') IS NULL THEN
    RAISE EXCEPTION 'Expected the Cal.com application schema';
  END IF;
  IF current_user <> 'postgres'
     OR NOT (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user)
     OR EXISTS (
       SELECT 1 FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'S')
         AND pg_get_userbyid(c.relowner) <> 'postgres'
     ) THEN
    RAISE EXCEPTION 'Verify the Cal.com server role and object ownership before applying';
  END IF;

  -- Schema access is an additional barrier for current and future objects.
  -- The server owner and the explicitly granted service_role retain access.
  REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC, anon, authenticated;
  REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC, anon, authenticated;
  REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, anon, authenticated;
  REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;

  -- Default deny for browser roles. No public policies are needed for this
  -- server-only database. Do not FORCE RLS on the server's table owner.
  FOR relation IN
    SELECT n.nspname, c.relname FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
    ORDER BY c.relname
  LOOP
    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', relation.nspname, relation.relname);
  END LOOP;

  -- Views must also respect their caller's permissions.
  FOR relation IN
    SELECT n.nspname, c.relname FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'v'
    ORDER BY c.relname
  LOOP
    EXECUTE format('ALTER VIEW %I.%I SET (security_invoker = true)', relation.nspname, relation.relname);
  END LOOP;

  -- Prisma migrations use postgres. Prevent automatic API exposure on upgrade.
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, anon, authenticated;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, anon, authenticated;
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
    REVOKE ALL PRIVILEGES ON FUNCTIONS FROM PUBLIC, anon, authenticated;
  -- A schema-level revoke cannot remove PostgreSQL's global PUBLIC EXECUTE default.
  ALTER DEFAULT PRIVILEGES FOR ROLE postgres
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

  FOREACH api_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF has_schema_privilege(api_role, 'public', 'USAGE')
       OR EXISTS (
         SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v')
           AND has_table_privilege(api_role, c.oid, 'SELECT,INSERT,UPDATE,DELETE')
       )
       OR EXISTS (
         SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public' AND has_function_privilege(api_role, p.oid, 'EXECUTE')
       ) THEN
      RAISE EXCEPTION 'Public API access remains for role %', api_role;
    END IF;
  END LOOP;
END
$migration$;

NOTIFY pgrst, 'reload schema';
COMMIT;
