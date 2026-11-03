-- IGLESIA RENACER: rechazo de solicitudes y gestión de roles
-- Ejecutar una sola vez en Supabase > SQL Editor.
-- Rechazar conserva la cuenta de Auth, pero la deja bloqueada (activo=false).

BEGIN;

ALTER TABLE public.perfiles_app
  ADD COLUMN IF NOT EXISTS estado_solicitud TEXT;

UPDATE public.perfiles_app
SET estado_solicitud = CASE WHEN activo = TRUE THEN 'aprobado' ELSE 'pendiente' END
WHERE estado_solicitud IS NULL;

ALTER TABLE public.perfiles_app
  ALTER COLUMN estado_solicitud SET DEFAULT 'pendiente',
  ALTER COLUMN estado_solicitud SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.perfiles_app'::regclass
      AND conname = 'perfiles_app_estado_solicitud_check'
  ) THEN
    ALTER TABLE public.perfiles_app
      ADD CONSTRAINT perfiles_app_estado_solicitud_check
      CHECK (estado_solicitud IN ('pendiente', 'aprobado', 'rechazado'));
  END IF;
END $$;

-- Evita dejar el sistema sin ningún administrador activo.
CREATE OR REPLACE FUNCTION public.proteger_ultimo_admin_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  otros_admins_activos INTEGER;
BEGIN
  IF OLD.rol = 'admin'
     AND OLD.activo = TRUE
     AND (NEW.rol <> 'admin' OR NEW.activo = FALSE) THEN
    SELECT COUNT(*) INTO otros_admins_activos
    FROM public.perfiles_app
    WHERE rol = 'admin' AND activo = TRUE AND id <> OLD.id;

    IF otros_admins_activos = 0 THEN
      RAISE EXCEPTION 'No se puede quitar o desactivar al último administrador activo.';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS proteger_ultimo_admin_renacer ON public.perfiles_app;
CREATE TRIGGER proteger_ultimo_admin_renacer
BEFORE UPDATE OF rol, activo ON public.perfiles_app
FOR EACH ROW
EXECUTE FUNCTION public.proteger_ultimo_admin_renacer();

-- Las políticas RLS existentes restringen las modificaciones de perfiles a administradores.
COMMIT;

-- Verificación:
SELECT id, nombre, usuario, rol, activo, estado_solicitud
FROM public.perfiles_app
ORDER BY nombre;
