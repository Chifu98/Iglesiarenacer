-- Servidor conserva permisos de Escritura en los demás módulos,
-- pero solo puede consultar anuncios. Admin, Escritura, Pastor y Líder mantienen gestión.

BEGIN;

CREATE OR REPLACE FUNCTION public.app_puede_gestionar_anuncios()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.perfiles_app p
    WHERE p.id = auth.uid()
      AND p.activo = TRUE
      AND p.roles && ARRAY['admin','escritura','pastor','lider']::text[]
  );
$$;

REVOKE ALL ON FUNCTION public.app_puede_gestionar_anuncios() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.app_puede_gestionar_anuncios() TO authenticated;

DROP POLICY IF EXISTS anuncios_insertar_admin_escritura ON public.anuncios;
CREATE POLICY anuncios_insertar_admin_escritura
ON public.anuncios
FOR INSERT
TO authenticated
WITH CHECK (public.app_puede_gestionar_anuncios());

DROP POLICY IF EXISTS anuncios_actualizar_admin_escritura ON public.anuncios;
CREATE POLICY anuncios_actualizar_admin_escritura
ON public.anuncios
FOR UPDATE
TO authenticated
USING (public.app_puede_gestionar_anuncios())
WITH CHECK (public.app_puede_gestionar_anuncios());

DROP POLICY IF EXISTS anuncios_eliminar_admin_escritura ON public.anuncios;
CREATE POLICY anuncios_eliminar_admin_escritura
ON public.anuncios
FOR DELETE
TO authenticated
USING (public.app_puede_gestionar_anuncios());

COMMIT;
