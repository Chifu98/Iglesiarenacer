-- Restrict ministry applications to active, linked non-admin/non-pastor accounts.
-- Leaders and members (including accounts with Servidor ministry) use the same
-- per-ministry approval workflow; existing review permissions are unchanged.

CREATE OR REPLACE FUNCTION public.solicitar_ingreso_ministerio(p_ministerio text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $function$
DECLARE
  v_miembro_id text;
  v_estado text;
  v_id uuid;
BEGIN
  IF auth.uid() IS NULL OR NOT public.app_perfil_activo() THEN
    RAISE EXCEPTION 'Debes iniciar sesión con una cuenta activa.';
  END IF;

  IF public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') THEN
    RAISE EXCEPTION 'Administradores y pastores asignan ministerios directamente; no deben postular.';
  END IF;

  IF p_ministerio IS NULL OR p_ministerio NOT IN
    ('Alabanza','Servidor','Niños','Jóvenes','Oración','Evangelismo','Redes','Damas','Matrimonio','Hombres') THEN
    RAISE EXCEPTION 'Selecciona un ministerio válido.';
  END IF;

  SELECT p.miembro_id, m.status
    INTO v_miembro_id, v_estado
  FROM public.perfiles_app p
  JOIN public.miembros_app m ON m.id = p.miembro_id
  WHERE p.id = auth.uid() AND p.activo = true
  FOR UPDATE OF m;

  IF v_miembro_id IS NULL OR v_estado <> 'Activo' THEN
    RAISE EXCEPTION 'Tu cuenta debe estar vinculada a una ficha activa.';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.miembros_app m
    WHERE m.id = v_miembro_id AND (
      p_ministerio = ANY(COALESCE(m.ministries, ARRAY[]::text[]))
      OR COALESCE(m.ministry, 'General') = p_ministerio
    )
  ) THEN
    RAISE EXCEPTION 'Ya perteneces a este ministerio.';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.solicitudes_ministerio
    WHERE miembro_id = v_miembro_id
      AND ministerio = p_ministerio
      AND estado = 'pendiente'
  ) THEN
    RAISE EXCEPTION 'Ya tienes una solicitud pendiente para este ministerio.';
  END IF;

  INSERT INTO public.solicitudes_ministerio
    (miembro_id, solicitado_por, ministerio, estado, creado_en)
  VALUES
    (v_miembro_id, auth.uid(), p_ministerio, 'pendiente', now())
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$function$;

REVOKE ALL ON FUNCTION public.solicitar_ingreso_ministerio(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.solicitar_ingreso_ministerio(text) FROM anon;
GRANT EXECUTE ON FUNCTION public.solicitar_ingreso_ministerio(text) TO authenticated;
