-- IGLESIA RENACER: registro público de nuevos miembros con aprobación administrativa
-- Ejecutar una sola vez en Supabase > SQL Editor después de desplegar la interfaz.
-- Las solicitudes se guardan separadas de miembros_app y no son visibles al público.

BEGIN;

CREATE TABLE IF NOT EXISTS public.solicitudes_membresia (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nombre TEXT NOT NULL CHECK (char_length(btrim(nombre)) BETWEEN 2 AND 120),
  telefono TEXT NOT NULL CHECK (char_length(btrim(telefono)) BETWEEN 6 AND 30),
  correo TEXT,
  direccion TEXT,
  estado_civil TEXT NOT NULL DEFAULT 'Soltero (a)'
    CHECK (estado_civil IN ('Soltero (a)', 'Novio (a)', 'Casado (a)', 'Viudo (a)')),
  nombre_pareja TEXT,
  ministerio TEXT NOT NULL DEFAULT 'General',
  bautizado TEXT NOT NULL DEFAULT 'No' CHECK (bautizado IN ('Sí', 'No')),
  fecha_nacimiento DATE NOT NULL,
  estado_solicitud TEXT NOT NULL DEFAULT 'pendiente'
    CHECK (estado_solicitud IN ('pendiente', 'aprobada', 'rechazada')),
  miembro_id TEXT REFERENCES public.miembros_app(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at TIMESTAMPTZ,
  reviewed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_solicitudes_membresia_estado_fecha
  ON public.solicitudes_membresia (estado_solicitud, created_at DESC);

ALTER TABLE public.solicitudes_membresia ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.solicitudes_membresia FROM anon, authenticated;
GRANT INSERT (
  nombre, telefono, correo, direccion, estado_civil, nombre_pareja,
  ministerio, bautizado, fecha_nacimiento
) ON public.solicitudes_membresia TO anon;
GRANT SELECT ON public.solicitudes_membresia TO authenticated;

DROP POLICY IF EXISTS solicitudes_membresia_public_insert
  ON public.solicitudes_membresia;
CREATE POLICY solicitudes_membresia_public_insert
ON public.solicitudes_membresia
FOR INSERT TO anon
WITH CHECK (estado_solicitud = 'pendiente' AND miembro_id IS NULL);

DROP POLICY IF EXISTS solicitudes_membresia_admin_select
  ON public.solicitudes_membresia;
CREATE POLICY solicitudes_membresia_admin_select
ON public.solicitudes_membresia
FOR SELECT TO authenticated
USING (public.app_rol_actual() = 'admin');

CREATE OR REPLACE FUNCTION public.aprobar_solicitud_membresia(p_solicitud_id UUID)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  solicitud public.solicitudes_membresia%ROWTYPE;
  nuevo_miembro_id TEXT;
BEGIN
  IF public.app_rol_actual() IS DISTINCT FROM 'admin' THEN
    RAISE EXCEPTION 'Solo un administrador puede aprobar solicitudes.';
  END IF;

  SELECT * INTO solicitud
  FROM public.solicitudes_membresia
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
    id, name, phone, email, address, marital_status, spouse_type,
    spouse_name, ministry, status, baptized, birthday, created_at, updated_at
  ) VALUES (
    nuevo_miembro_id,
    solicitud.nombre,
    solicitud.telefono,
    NULLIF(btrim(COALESCE(solicitud.correo, '')), ''),
    NULLIF(btrim(COALESCE(solicitud.direccion, '')), ''),
    solicitud.estado_civil,
    CASE
      WHEN solicitud.estado_civil IN ('Casado (a)', 'Novio (a)')
        AND NULLIF(btrim(COALESCE(solicitud.nombre_pareja, '')), '') IS NOT NULL
      THEN 'text'
      ELSE 'none'
    END,
    NULLIF(btrim(COALESCE(solicitud.nombre_pareja, '')), ''),
    COALESCE(NULLIF(btrim(solicitud.ministerio), ''), 'General'),
    'Activo',
    solicitud.bautizado,
    solicitud.fecha_nacimiento,
    now(),
    now()
  );

  UPDATE public.solicitudes_membresia
  SET estado_solicitud = 'aprobada',
      miembro_id = nuevo_miembro_id,
      reviewed_at = now(),
      reviewed_by = auth.uid()
  WHERE id = p_solicitud_id;

  RETURN nuevo_miembro_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.rechazar_solicitud_membresia(p_solicitud_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
  IF public.app_rol_actual() IS DISTINCT FROM 'admin' THEN
    RAISE EXCEPTION 'Solo un administrador puede rechazar solicitudes.';
  END IF;

  UPDATE public.solicitudes_membresia
  SET estado_solicitud = 'rechazada',
      reviewed_at = now(),
      reviewed_by = auth.uid()
  WHERE id = p_solicitud_id
    AND estado_solicitud = 'pendiente';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'La solicitud no existe o ya fue revisada.';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.aprobar_solicitud_membresia(UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.rechazar_solicitud_membresia(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.aprobar_solicitud_membresia(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.rechazar_solicitud_membresia(UUID) TO authenticated;

COMMIT;

-- Verificación
SELECT estado_solicitud, COUNT(*)
FROM public.solicitudes_membresia
GROUP BY estado_solicitud;
