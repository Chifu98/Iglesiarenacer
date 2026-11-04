-- Datos de seguimiento de invitaciones para personas en estado "En Visita".
ALTER TABLE public.miembros_app
  ADD COLUMN IF NOT EXISTS inviter_member_id text,
  ADD COLUMN IF NOT EXISTS inviter_name text,
  ADD COLUMN IF NOT EXISTS inviter_relationship text;

-- Al convertir una visita en miembro activo, eliminar estos datos también
-- desde la base de datos, independientemente del cliente que realice el cambio.
CREATE OR REPLACE FUNCTION public.limpiar_datos_invitacion_miembro_activo()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF NEW.status = 'Activo' THEN
    NEW.inviter_member_id := NULL;
    NEW.inviter_name := NULL;
    NEW.inviter_relationship := NULL;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_limpiar_datos_invitacion_miembro_activo ON public.miembros_app;
CREATE TRIGGER trg_limpiar_datos_invitacion_miembro_activo
BEFORE INSERT OR UPDATE OF status ON public.miembros_app
FOR EACH ROW
EXECUTE FUNCTION public.limpiar_datos_invitacion_miembro_activo();
