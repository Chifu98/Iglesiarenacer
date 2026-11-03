-- Renacer: acceso compartido a notas pastorales y nuevo espacio de notas de líderes.
BEGIN;

-- Reemplaza las políticas de notas pastorales para que Admin y Pastor tengan CRUD completo.
DO $$
DECLARE p record;
BEGIN
  FOR p IN SELECT policyname FROM pg_policies
    WHERE schemaname='public' AND tablename='notas_pastorales'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.notas_pastorales', p.policyname);
  END LOOP;
END $$;

CREATE POLICY notas_pastorales_select ON public.notas_pastorales
FOR SELECT TO authenticated
USING (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor'));
CREATE POLICY notas_pastorales_insert ON public.notas_pastorales
FOR INSERT TO authenticated
WITH CHECK (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor'));
CREATE POLICY notas_pastorales_update ON public.notas_pastorales
FOR UPDATE TO authenticated
USING (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor'))
WITH CHECK (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor'));
CREATE POLICY notas_pastorales_delete ON public.notas_pastorales
FOR DELETE TO authenticated
USING (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor'));

-- Nueva tabla independiente para notas compartidas entre Admin, Pastor y Líder.
CREATE TABLE IF NOT EXISTS public.notas_lideres (
  miembro_id text PRIMARY KEY REFERENCES public.miembros_app(id) ON DELETE CASCADE,
  nota text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES auth.users(id) ON DELETE SET NULL
);
ALTER TABLE public.notas_lideres ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS notas_lideres_select ON public.notas_lideres;
DROP POLICY IF EXISTS notas_lideres_insert ON public.notas_lideres;
DROP POLICY IF EXISTS notas_lideres_update ON public.notas_lideres;
DROP POLICY IF EXISTS notas_lideres_delete ON public.notas_lideres;

CREATE POLICY notas_lideres_select ON public.notas_lideres
FOR SELECT TO authenticated
USING (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor') OR public.app_tiene_rol('lider'));
CREATE POLICY notas_lideres_insert ON public.notas_lideres
FOR INSERT TO authenticated
WITH CHECK (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor') OR public.app_tiene_rol('lider'));
CREATE POLICY notas_lideres_update ON public.notas_lideres
FOR UPDATE TO authenticated
USING (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor') OR public.app_tiene_rol('lider'))
WITH CHECK (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor') OR public.app_tiene_rol('lider'));
CREATE POLICY notas_lideres_delete ON public.notas_lideres
FOR DELETE TO authenticated
USING (public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor') OR public.app_tiene_rol('lider'));

GRANT SELECT, INSERT, UPDATE, DELETE ON public.notas_lideres TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.notas_pastorales TO authenticated;

DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.notas_lideres;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

COMMIT;
