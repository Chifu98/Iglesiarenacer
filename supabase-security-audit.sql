-- AUDITORÍA DE CONFIGURACIÓN RLS Y REALTIME - IGLESIA RENACER
-- Ejecutar en Supabase > SQL Editor.
-- Este reporte revisa la configuración; no sustituye las pruebas iniciando sesión
-- con cuentas admin, escritura y lectura desde la aplicación.

-- 1) RLS debe estar activado en las cuatro tablas.
SELECT
  n.nspname AS esquema,
  c.relname AS tabla,
  c.relrowsecurity AS rls_activado,
  c.relforcerowsecurity AS rls_forzado
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname IN (
    'perfiles_app',
    'miembros_app',
    'peticiones_oracion',
    'notas_pastorales'
  )
ORDER BY c.relname;

-- 2) Políticas aplicadas por tabla.
SELECT
  tablename,
  policyname,
  roles,
  cmd,
  qual AS condicion_lectura_o_borrado,
  with_check AS condicion_escritura
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename IN (
    'perfiles_app',
    'miembros_app',
    'peticiones_oracion',
    'notas_pastorales'
  )
ORDER BY tablename, policyname;

-- 3) Privilegios SQL asignados a anon y authenticated.
SELECT
  table_name,
  grantee,
  privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND table_name IN (
    'perfiles_app',
    'miembros_app',
    'peticiones_oracion',
    'notas_pastorales'
  )
  AND grantee IN ('anon', 'authenticated')
ORDER BY table_name, grantee, privilege_type;

-- 4) La columna notes NO debe seguir en miembros_app.
SELECT column_name
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'miembros_app'
  AND column_name = 'notes';

-- 5) Las cuatro tablas deben estar publicadas para Realtime.
SELECT
  tablename
FROM pg_publication_tables
WHERE pubname = 'supabase_realtime'
  AND schemaname = 'public'
  AND tablename IN (
    'miembros_app',
    'peticiones_oracion',
    'notas_pastorales'
  )
ORDER BY tablename;

-- 6) La función de rol debe existir y ejecutarse como SECURITY DEFINER.
SELECT
  p.proname AS funcion,
  p.prosecdef AS security_definer,
  pg_get_userbyid(p.proowner) AS propietario
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.proname = 'app_rol_actual';
