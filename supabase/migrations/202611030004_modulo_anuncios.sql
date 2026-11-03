-- Módulo de anuncios congregacionales
-- Ejecutar una sola vez en Supabase SQL Editor.

BEGIN;

CREATE TABLE IF NOT EXISTS public.anuncios (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  titulo text NOT NULL CHECK (char_length(btrim(titulo)) BETWEEN 3 AND 150),
  contenido text NOT NULL CHECK (char_length(btrim(contenido)) BETWEEN 3 AND 10000),
  creado_por uuid NOT NULL REFERENCES auth.users(id) ON DELETE RESTRICT DEFAULT auth.uid(),
  creado_en timestamptz NOT NULL DEFAULT now(),
  actualizado_en timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.anuncios ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS anuncios_lectura_usuarios_activos ON public.anuncios;
CREATE POLICY anuncios_lectura_usuarios_activos
ON public.anuncios
FOR SELECT
TO authenticated
USING (public.app_tiene_rol('hermano'));

DROP POLICY IF EXISTS anuncios_insertar_admin_escritura ON public.anuncios;
CREATE POLICY anuncios_insertar_admin_escritura
ON public.anuncios
FOR INSERT
TO authenticated
WITH CHECK (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('escritura')
);

DROP POLICY IF EXISTS anuncios_actualizar_admin_escritura ON public.anuncios;
CREATE POLICY anuncios_actualizar_admin_escritura
ON public.anuncios
FOR UPDATE
TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('escritura')
)
WITH CHECK (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('escritura')
);

DROP POLICY IF EXISTS anuncios_eliminar_admin_escritura ON public.anuncios;
CREATE POLICY anuncios_eliminar_admin_escritura
ON public.anuncios
FOR DELETE
TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('escritura')
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.anuncios TO authenticated;
GRANT SELECT ON public.anuncios TO anon;

CREATE INDEX IF NOT EXISTS anuncios_creado_en_idx
ON public.anuncios (creado_en DESC);

COMMIT;
