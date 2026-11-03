-- Iglesia Renacer: permisos del rol lectura para peticiones de oración
-- Ejecutar en Supabase SQL Editor después de publicar la versión web correspondiente.
-- Este script reemplaza las políticas RLS de miembros_app y peticiones_oracion.
-- No modifica las políticas de perfiles_app ni notas_pastorales.

DO $$
DECLARE
  policy_row RECORD;
BEGIN
  FOR policy_row IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename IN ('miembros_app', 'peticiones_oracion')
  LOOP
    EXECUTE format(
      'DROP POLICY IF EXISTS %I ON %I.%I',
      policy_row.policyname,
      policy_row.schemaname,
      policy_row.tablename
    );
  END LOOP;
END
$$;

ALTER TABLE public.miembros_app ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.peticiones_oracion ENABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.miembros_app TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.peticiones_oracion TO authenticated;

-- Todos los roles activos pueden consultar los registros congregacionales.
CREATE POLICY miembros_select_roles
ON public.miembros_app
FOR SELECT
TO authenticated
USING (public.app_rol_actual() IN ('admin', 'escritura', 'lectura'));

-- Solo administración y escritura pueden crear, modificar o eliminar miembros.
CREATE POLICY miembros_insert_admin_escritura
ON public.miembros_app
FOR INSERT
TO authenticated
WITH CHECK (public.app_rol_actual() IN ('admin', 'escritura'));

CREATE POLICY miembros_update_admin_escritura
ON public.miembros_app
FOR UPDATE
TO authenticated
USING (public.app_rol_actual() IN ('admin', 'escritura'))
WITH CHECK (public.app_rol_actual() IN ('admin', 'escritura'));

CREATE POLICY miembros_delete_admin_escritura
ON public.miembros_app
FOR DELETE
TO authenticated
USING (public.app_rol_actual() IN ('admin', 'escritura'));

-- Todos los roles activos pueden ver las peticiones.
CREATE POLICY peticiones_select_roles
ON public.peticiones_oracion
FOR SELECT
TO authenticated
USING (public.app_rol_actual() IN ('admin', 'escritura', 'lectura'));

-- Los tres roles pueden crear peticiones.
CREATE POLICY peticiones_insert_roles
ON public.peticiones_oracion
FOR INSERT
TO authenticated
WITH CHECK (public.app_rol_actual() IN ('admin', 'escritura', 'lectura'));

-- Lectura no puede editar ni eliminar peticiones.
CREATE POLICY peticiones_update_admin_escritura
ON public.peticiones_oracion
FOR UPDATE
TO authenticated
USING (public.app_rol_actual() IN ('admin', 'escritura'))
WITH CHECK (public.app_rol_actual() IN ('admin', 'escritura'));

CREATE POLICY peticiones_delete_admin_escritura
ON public.peticiones_oracion
FOR DELETE
TO authenticated
USING (public.app_rol_actual() IN ('admin', 'escritura'));

-- Verificación rápida: muestra las políticas activas de ambas tablas.
SELECT tablename, policyname, cmd, roles, qual, with_check
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename IN ('miembros_app', 'peticiones_oracion')
ORDER BY tablename, policyname;
