-- Exigir que todo perfil con rol Líder tenga una ficha activa y un único ministerio concreto.
-- Los líderes no pueden quedar asignados a General ni perder su ministerio mientras mantengan el rol.
BEGIN;

CREATE OR REPLACE FUNCTION private.app_ministerio_lider_actual()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO 'pg_catalog'
AS $function$
  SELECT m.ministry
  FROM public.perfiles_app p
  JOIN public.miembros_app m ON m.id = p.miembro_id
  WHERE p.id = (SELECT auth.uid())
    AND p.activo = true
    AND p.roles @> ARRAY['lider']::text[]
    AND m.status = 'Activo'
    AND COALESCE(m.ministry, 'General') <> 'General'
  LIMIT 1;
$function$;

CREATE OR REPLACE FUNCTION private.validar_lider_ministerio_perfil()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog'
AS $function$
DECLARE
  v_ministerio text;
  v_estado text;
BEGIN
  IF NEW.roles @> ARRAY['lider']::text[] THEN
    IF NEW.miembro_id IS NULL THEN
      RAISE EXCEPTION 'Para asignar el rol Líder, la cuenta debe estar vinculada a una ficha personal.';
    END IF;

    SELECT m.ministry, m.status
      INTO v_ministerio, v_estado
    FROM public.miembros_app m
    WHERE m.id = NEW.miembro_id;

    IF NOT FOUND OR v_estado <> 'Activo' OR COALESCE(v_ministerio, 'General') = 'General' THEN
      RAISE EXCEPTION 'Para asignar el rol Líder, la ficha asociada debe estar Activa y pertenecer a un ministerio distinto de General.';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION private.proteger_ministerio_de_lider()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog'
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF EXISTS (
      SELECT 1 FROM public.perfiles_app p
      WHERE p.miembro_id = OLD.id AND p.roles @> ARRAY['lider']::text[]
    ) THEN
      RAISE EXCEPTION 'No puedes eliminar la ficha asociada a un Líder. Primero cambia su rol o vincula otra ficha.';
    END IF;
    RETURN OLD;
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.perfiles_app p
    WHERE p.miembro_id = NEW.id AND p.roles @> ARRAY['lider']::text[]
  ) AND (NEW.status <> 'Activo' OR COALESCE(NEW.ministry, 'General') = 'General') THEN
    RAISE EXCEPTION 'Un Líder debe conservar una ficha Activa y un ministerio asignado. Cambia su rol antes de quitar el ministerio o inactivar la ficha.';
  END IF;
  RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION private.validar_lider_ministerio_perfil() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION private.proteger_ministerio_de_lider() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS zz_perfiles_app_validar_lider_ministerio ON public.perfiles_app;
CREATE TRIGGER zz_perfiles_app_validar_lider_ministerio
BEFORE INSERT OR UPDATE OF roles, rol, miembro_id, activo
ON public.perfiles_app
FOR EACH ROW EXECUTE FUNCTION private.validar_lider_ministerio_perfil();

DROP TRIGGER IF EXISTS zz_miembros_app_proteger_ministerio_lider ON public.miembros_app;
CREATE TRIGGER zz_miembros_app_proteger_ministerio_lider
BEFORE DELETE OR UPDATE OF ministry, status
ON public.miembros_app
FOR EACH ROW EXECUTE FUNCTION private.proteger_ministerio_de_lider();

COMMENT ON FUNCTION private.app_ministerio_lider_actual() IS
'Devuelve el único ministerio de la ficha activa asociada al líder; NULL si no existe una asignación válida.';
COMMENT ON FUNCTION private.validar_lider_ministerio_perfil() IS
'Impide asignar el rol Líder sin una ficha activa vinculada y un ministerio distinto de General.';
COMMENT ON FUNCTION private.proteger_ministerio_de_lider() IS
'Impide dejar sin ministerio, inactivar o eliminar la ficha asociada a una cuenta con rol Líder.';

COMMIT;
