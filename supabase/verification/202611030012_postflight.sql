-- VERIFICACIÓN POST-MIGRACIÓN 012 — SOLO LECTURA
-- Ejecutar en Supabase SQL Editor después de aplicar la migración.
-- No modifica tablas, permisos ni datos.

-- 1. Confirmar que existe el modelo de roles y su trigger.
SELECT
  EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='perfiles_app' AND column_name='roles'
  ) AS columna_roles_existe,
  EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid='public.perfiles_app'::regclass
      AND conname='perfiles_app_roles_check'
  ) AS restriccion_roles_existe,
  EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgrelid='public.perfiles_app'::regclass
      AND tgname='perfiles_app_sincronizar_roles'
      AND NOT tgisinternal
  ) AS trigger_roles_existe;

-- 2. Resumen de los roles explícitos asignados.
SELECT role_name, COUNT(*) AS perfiles
FROM public.perfiles_app p
CROSS JOIN LATERAL unnest(p.roles) AS x(role_name)
GROUP BY role_name
ORDER BY role_name;

-- 3. Debe devolver cero filas: roles nulos, vacíos, duplicados o desconocidos.
SELECT id, usuario, roles
FROM public.perfiles_app p
WHERE roles IS NULL
   OR cardinality(roles) = 0
   OR EXISTS (
     SELECT 1
     FROM unnest(roles) AS x(role_name)
     WHERE role_name NOT IN ('admin','escritura','lectura','pastor','lider','servidor','hermano')
   )
   OR cardinality(roles) <> (
     SELECT COUNT(DISTINCT role_name)::integer
     FROM unnest(roles) AS x(role_name)
   );

-- 4. Debe devolver cero filas: más de una nota del mismo líder para el mismo miembro.
SELECT miembro_id, lider_id, COUNT(*) AS cantidad
FROM public.notas_lideres
GROUP BY miembro_id, lider_id
HAVING COUNT(*) > 1;

-- 5. Revisar notas sin autor. Solo Admin/Pastor deberían poder verlas.
SELECT COUNT(*) AS notas_sin_lider
FROM public.notas_lideres
WHERE lider_id IS NULL;

-- 6. Revisar políticas RLS de las tablas sensibles.
SELECT tablename, policyname, cmd, roles, qual, with_check
FROM pg_policies
WHERE schemaname='public'
  AND tablename IN (
    'perfiles_app','miembros_app','miembros',
    'notas_lideres','notas_pastorales',
    'peticiones_oracion','anuncios','avisos_congregacion'
  )
ORDER BY tablename, policyname;

-- 7. Confirmar que anon no tenga permisos sobre notas de líderes.
SELECT
  has_table_privilege('anon','public.notas_lideres','SELECT') AS anon_puede_leer_notas,
  has_table_privilege('anon','public.notas_lideres','INSERT') AS anon_puede_insertar_notas,
  has_table_privilege('authenticated','public.notas_lideres','SELECT') AS usuarios_autenticados_pueden_consultar;

-- 8. Confirmar permisos de ejecución de funciones auxiliares.
SELECT
  has_function_privilege('anon','public.app_tiene_rol(text)','EXECUTE') AS anon_ejecuta_app_tiene_rol,
  has_function_privilege('authenticated','public.app_tiene_rol(text)','EXECUTE') AS autenticados_ejecutan_app_tiene_rol,
  has_function_privilege('anon','public.app_rol_actual()','EXECUTE') AS anon_ejecuta_app_rol_actual,
  has_function_privilege('authenticated','public.app_rol_actual()','EXECUTE') AS autenticados_ejecutan_app_rol_actual;
