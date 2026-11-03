-- Iglesia Renacer: registro público con aprobación administrativa obligatoria.
-- Ejecutar en Supabase SQL Editor antes de habilitar el formulario en producción.
-- Las cuentas nuevas se crean con rol lectura y activo=false.
-- Solo un administrador activo puede aprobarlas cambiando activo=true.

CREATE OR REPLACE FUNCTION public.crear_perfil_pendiente_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  nombre_usuario text;
BEGIN
  nombre_usuario := COALESCE(
    NULLIF(trim(NEW.raw_user_meta_data ->> 'nombre'), ''),
    split_part(COALESCE(NEW.email, ''), '@', 1),
    'Usuario'
  );

  IF NEW.email IS NOT NULL THEN
    INSERT INTO public.perfiles_app (id, nombre, usuario, rol, activo)
    VALUES (NEW.id, nombre_usuario, lower(NEW.email), 'lectura', false)
    ON CONFLICT (id) DO NOTHING;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS crear_perfil_pendiente_renacer ON auth.users;
CREATE TRIGGER crear_perfil_pendiente_renacer
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.crear_perfil_pendiente_renacer();

-- El usuario autenticado puede consultar únicamente su propio perfil.
-- El administrador puede consultar todos y aprobar cuentas pendientes.
ALTER TABLE public.perfiles_app ENABLE ROW LEVEL SECURITY;
GRANT SELECT, UPDATE ON public.perfiles_app TO authenticated;

DROP POLICY IF EXISTS perfiles_select_propio_o_admin_renacer ON public.perfiles_app;
CREATE POLICY perfiles_select_propio_o_admin_renacer
ON public.perfiles_app
FOR SELECT
TO authenticated
USING (
  id = auth.uid()
  OR public.app_rol_actual() = 'admin'
);

DROP POLICY IF EXISTS perfiles_update_solo_admin_renacer ON public.perfiles_app;
CREATE POLICY perfiles_update_solo_admin_renacer
ON public.perfiles_app
FOR UPDATE
TO authenticated
USING (public.app_rol_actual() = 'admin')
WITH CHECK (public.app_rol_actual() = 'admin');

-- Verificación de trigger y políticas.
SELECT
  trigger_name, event_manipulation, event_object_schema, event_object_table
FROM information_schema.triggers
WHERE trigger_schema = 'auth'
  AND event_object_table = 'users'
  AND trigger_name = 'crear_perfil_pendiente_renacer';

SELECT policyname, cmd, roles
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename = 'perfiles_app'
ORDER BY policyname;
