-- IGLESIA RENACER: registro público de nuevos miembros con aprobación administrativa
-- Ejecutar una sola vez en Supabase > SQL Editor.
-- Las solicitudes públicas no pueden leer ni modificar otras solicitudes.
-- Solo administradores pueden consultar, aprobar o rechazar registros.

BEGIN;

CREATE TABLE IF NOT EXISTS public.solicitudes_registro_miembros (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL CHECK (char_length(btrim(name)) BETWEEN 3 AND 150),
  phone TEXT NOT NULL CHECK (char_length(btrim(phone)) BETWEEN 7 AND 30),
  email TEXT,
  address TEXT,
  marital_status TEXT NOT NULL DEFAULT 'Soltero (a)'
    CHECK (marital_status IN ('Soltero (a)', 'Novio (a)', 'Casado (a)', 'Viudo (a)')),
  spouse_type TEXT NOT NULL DEFAULT 'none'
    CHECK (spouse_type IN ('none', 'text')),
  spouse_name TEXT,
  spouse_id TEXT,
  ministry TEXT NOT NULL DEFAULT 'General'
    CHECK (ministry IN ('General', 'Alabanza', 'Servidor', 'Niños', 'Jóvenes', 'Oración', 'Evangelismo')),
  status TEXT NOT NULL DEFAULT 'Activo' CHECK (status = 'Activo'),
  baptized TEXT NOT NULL DEFAULT 'No' CHECK (baptized IN ('Sí', 'No')),
  birthday DATE NOT NULL,
  estado_solicitud TEXT NOT NULL DEFAULT 'pendiente'
    CHECK (estado_solicitud IN ('pendiente', 'aprobado', 'rechazado')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at TIMESTAMPTZ,
  reviewed_by UUID REFERENCES auth.users(id)
);

ALTER TABLE public.solicitudes_registro_miembros ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS solicitudes_miembros_public_insert ON public.solicitudes_registro_miembros;
CREATE POLICY solicitudes_miembros_public_insert
  ON public.solicitudes_registro_miembros
  FOR INSERT TO anon, authenticated
  WITH CHECK (
    estado_solicitud = 'pendiente'
    AND status = 'Activo'
    AND char_length(btrim(name)) BETWEEN 3 AND 150
    AND char_length(btrim(phone)) BETWEEN 7 AND 30
  );

DROP POLICY IF EXISTS solicitudes_miembros_admin_select ON public.solicitudes_registro_miembros;
CREATE POLICY solicitudes_miembros_admin_select
  ON public.solicitudes_registro_miembros
  FOR SELECT TO authenticated
  USING (public.app_rol_actual() = 'admin');

DROP POLICY IF EXISTS solicitudes_miembros_admin_update ON public.solicitudes_registro_miembros;
CREATE POLICY solicitudes_miembros_admin_update
  ON public.solicitudes_registro_miembros
  FOR UPDATE TO authenticated
  USING (public.app_rol_actual() = 'admin')
  WITH CHECK (public.app_rol_actual() = 'admin');

GRANT INSERT ON TABLE public.solicitudes_registro_miembros TO anon, authenticated;
GRANT SELECT, UPDATE ON TABLE public.solicitudes_registro_miembros TO authenticated;

CREATE INDEX IF NOT EXISTS idx_solicitudes_miembros_estado_fecha
  ON public.solicitudes_registro_miembros (estado_solicitud, created_at);

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

  nuevo_miembro_id := gen_random_uuid()::TEXT;

  INSERT INTO public.miembros_app (
    id, name, phone, email, address, marital_status,
    spouse_type, spouse_name, spouse_id, ministry, status,
    baptized, birthday, avatar, created_at, updated_at, created_by
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
    NOW(),
    auth.uid()
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

COMMIT;

-- Verificación: ejecutar como administrador después de enviar una solicitud.
SELECT id, name, phone, email, ministry, estado_solicitud, created_at
FROM public.solicitudes_registro_miembros
ORDER BY created_at DESC;
