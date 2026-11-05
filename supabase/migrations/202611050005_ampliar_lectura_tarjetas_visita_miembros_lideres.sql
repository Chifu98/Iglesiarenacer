-- Miembros y líderes activos pueden consultar todas las tarjetas de visita sin leer fichas generales.
CREATE OR REPLACE FUNCTION public.listar_tarjetas_visita_servidor()
RETURNS TABLE(
  id text,
  name text,
  status text,
  created_at timestamptz,
  inviter_name text,
  inviter_relationship text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
BEGIN
  IF auth.uid() IS NULL OR NOT EXISTS (
    SELECT 1
    FROM public.perfiles_app AS p
    LEFT JOIN public.miembros_app AS own_member
      ON own_member.id = p.miembro_id
    WHERE p.id = (SELECT auth.uid())
      AND p.activo IS TRUE
      AND (
        COALESCE(p.roles, ARRAY[]::text[]) && ARRAY['admin','pastor','lider','miembro','hermano']::text[]
        OR p.rol IN ('admin','pastor','lider','miembro','hermano')
        OR own_member.ministry = 'Servidor'
      )
  ) THEN
    RAISE EXCEPTION 'Acceso no autorizado';
  END IF;

  RETURN QUERY
  SELECT m.id::text, m.name, m.status, m.created_at,
         m.inviter_name, m.inviter_relationship
  FROM public.miembros_app AS m
  WHERE m.status = 'En Visita'
  ORDER BY m.created_at DESC;
END;
$function$;

REVOKE ALL ON FUNCTION public.listar_tarjetas_visita_servidor() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.listar_tarjetas_visita_servidor() FROM anon;
GRANT EXECUTE ON FUNCTION public.listar_tarjetas_visita_servidor() TO authenticated;
