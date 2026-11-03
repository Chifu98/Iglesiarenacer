-- IGLESIA RENACER: corrección segura de la aprobación de solicitudes públicas.
-- Ejecutar UNA VEZ si ya se ejecutó supabase-registro-publico-miembros.sql.
-- No modifica registros existentes ni las políticas de las demás tablas.

CREATE OR REPLACE FUNCTION public.aprobar_solicitud_registro_miembro(p_solicitud_id UUID)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  solicitud public.solicitudes_registro_miembros%ROWTYPE;
  nuevo_miembro_id TEXT;
BEGIN
  IF auth.uid() IS NULL OR public.app_rol_actual() <> 'admin' THEN
    RAISE EXCEPTION 'Solo un administrador puede aprobar solicitudes de miembros.';
  END IF;

  SELECT * INTO solicitud
  FROM public.solicitudes_registro_miembros
  WHERE id = p_solicitud_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'La solicitud no existe.';
  END IF;

  IF solicitud.estado_solicitud <> 'pendiente' THEN
    RAISE EXCEPTION 'La solicitud ya fue revisada.';
  END IF;

  IF solicitud.email IS NOT NULL AND EXISTS (
    SELECT 1
    FROM public.miembros_app AS m
    WHERE lower(trim(m.email)) = lower(trim(solicitud.email))
  ) THEN
    RAISE EXCEPTION 'Ya existe un hermano registrado con ese correo electrónico.';
  END IF;

  nuevo_miembro_id := gen_random_uuid()::TEXT;

  INSERT INTO public.miembros_app (
    id, name, phone, email, address, marital_status,
    spouse_type, spouse_name, spouse_id, ministry, status,
    baptized, birthday, avatar, created_at, updated_at
  ) VALUES (
    nuevo_miembro_id,
    solicitud.name,
    solicitud.phone,
    solicitud.email,
    solicitud.address,
    solicitud.marital_status,
    solicitud.spouse_type,
    solicitud.spouse_name,
    NULL,
    solicitud.ministry,
    'Activo',
    solicitud.baptized,
    solicitud.birthday,
    NULL,
    NOW(),
    NOW()
  );

  UPDATE public.solicitudes_registro_miembros
  SET estado_solicitud = 'aprobado',
      reviewed_at = NOW(),
      reviewed_by = auth.uid()
  WHERE id = p_solicitud_id;

  RETURN nuevo_miembro_id;
END;
$$;

REVOKE ALL ON FUNCTION public.aprobar_solicitud_registro_miembro(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.aprobar_solicitud_registro_miembro(UUID) TO authenticated;
