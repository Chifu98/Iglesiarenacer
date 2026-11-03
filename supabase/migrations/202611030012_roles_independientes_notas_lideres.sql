-- Renacer: roles independientes y notas de líderes por autor.
-- Esta migración supersede las restricciones heredadas de las migraciones 003-011.
-- No elimina filas ni concede directorio automáticamente a Pastor/Líder/Servidor.

BEGIN;

-- 1. Normalizar perfiles existentes sin añadir roles implícitos.
ALTER TABLE public.perfiles_app
  ADD COLUMN IF NOT EXISTS roles text[];

-- Desactivar temporalmente el trigger heredado, que forzaba hermano en cada perfil.
DROP TRIGGER IF EXISTS perfiles_app_sincronizar_roles ON public.perfiles_app;

UPDATE public.perfiles_app
SET roles = CASE
  WHEN rol IS NOT NULL THEN ARRAY[rol]::text[]
  ELSE ARRAY['hermano']::text[]
END
WHERE roles IS NULL OR cardinality(roles) = 0;

-- Las migraciones anteriores agregaban hermano automáticamente a todo rol especializado.
-- Quitamos esa herencia histórica; las combinaciones explícitas posteriores se conservan.
UPDATE public.perfiles_app
SET roles = array_remove(roles, 'hermano')
WHERE cardinality(roles) > 1
  AND roles @> ARRAY['hermano']::text[];

ALTER TABLE public.perfiles_app
  ALTER COLUMN roles SET DEFAULT ARRAY['hermano']::text[],
  ALTER COLUMN roles SET NOT NULL;

CREATE OR REPLACE FUNCTION public.app_roles_valid(p_roles text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT p_roles IS NOT NULL
    AND cardinality(p_roles) BETWEEN 1 AND 7
    AND p_roles <@ ARRAY['admin','escritura','lectura','pastor','lider','servidor','hermano']::text[]
    AND cardinality(p_roles) = (
      SELECT COUNT(DISTINCT role_name)::integer
      FROM unnest(p_roles) AS role_name
    );
$$;

REVOKE ALL ON FUNCTION public.app_roles_valid(text[]) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.app_roles_valid(text[]) TO authenticated, service_role;

ALTER TABLE public.perfiles_app
  DROP CONSTRAINT IF EXISTS perfiles_app_roles_check;

ALTER TABLE public.perfiles_app
  ADD CONSTRAINT perfiles_app_roles_check
  CHECK (public.app_roles_valid(roles));

-- 2. Mantener rol como campo de compatibilidad, nunca como fuente de permisos.
CREATE OR REPLACE FUNCTION public.sincronizar_roles_perfil_renacer()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_roles text[];
BEGIN
  IF TG_OP = 'INSERT' AND (NEW.roles IS NULL OR NEW.roles = ARRAY['hermano']::text[]) THEN
    v_roles := ARRAY[COALESCE(NEW.rol, 'hermano')]::text[];
  ELSIF TG_OP = 'UPDATE' AND NEW.roles IS NOT DISTINCT FROM OLD.roles
        AND NEW.rol IS DISTINCT FROM OLD.rol THEN
    -- Compatibilidad con integraciones antiguas que solo actualizan rol.
    v_roles := ARRAY[COALESCE(NEW.rol, 'hermano')]::text[];
  ELSE
    v_roles := NEW.roles;
  END IF;

  IF v_roles IS NULL OR cardinality(v_roles) < 1 OR cardinality(v_roles) > 7
     OR EXISTS (
       SELECT 1 FROM unnest(v_roles) AS r
       WHERE r NOT IN ('admin','escritura','lectura','pastor','lider','servidor','hermano')
     )
     OR cardinality(v_roles) <> cardinality(ARRAY(SELECT DISTINCT unnest(v_roles))) THEN
    RAISE EXCEPTION 'Roles no válidos. Selecciona uno o más roles explícitos.';
  END IF;

  SELECT array_agg(r ORDER BY CASE r
    WHEN 'admin' THEN 1
    WHEN 'escritura' THEN 2
    WHEN 'lectura' THEN 3
    WHEN 'pastor' THEN 4
    WHEN 'lider' THEN 5
    WHEN 'servidor' THEN 6
    WHEN 'hermano' THEN 7
    ELSE 8 END)
  INTO v_roles
  FROM unnest(v_roles) AS r;

  NEW.roles := v_roles;
  NEW.rol := v_roles[1];
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS perfiles_app_sincronizar_roles ON public.perfiles_app;
CREATE TRIGGER perfiles_app_sincronizar_roles
BEFORE INSERT OR UPDATE OF roles, rol
ON public.perfiles_app
FOR EACH ROW
EXECUTE FUNCTION public.sincronizar_roles_perfil_renacer();

CREATE OR REPLACE FUNCTION public.app_tiene_rol(p_rol text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.perfiles_app p
    WHERE p.id = auth.uid()
      AND p.activo = TRUE
      AND p.roles @> ARRAY[p_rol]::text[]
  );
$$;

REVOKE ALL ON FUNCTION public.app_tiene_rol(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.app_tiene_rol(text) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION public.app_rol_actual()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT p.roles[1]
  FROM public.perfiles_app p
  WHERE p.id = auth.uid() AND p.activo = TRUE
  LIMIT 1;
$$;

REVOKE ALL ON FUNCTION public.app_rol_actual() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.app_rol_actual() TO authenticated, service_role;

CREATE OR REPLACE FUNCTION public.app_puede_gestionar_anuncios()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT public.app_tiene_rol('admin') OR public.app_tiene_rol('escritura');
$$;

REVOKE ALL ON FUNCTION public.app_puede_gestionar_anuncios() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.app_puede_gestionar_anuncios() TO authenticated, service_role;

-- 3. Notas de líderes: conservar notas históricas y dar una fila por miembro/líder.
ALTER TABLE public.notas_lideres
  ADD COLUMN IF NOT EXISTS lider_id uuid;

UPDATE public.notas_lideres
SET lider_id = updated_by
WHERE lider_id IS NULL AND updated_by IS NOT NULL;

DO $$
DECLARE
  pk_name text;
  pk_cols text[];
BEGIN
  SELECT c.conname, array_agg(a.attname ORDER BY u.ord)
  INTO pk_name, pk_cols
  FROM pg_constraint c
  JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS u(attnum, ord) ON true
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = u.attnum
  WHERE c.conrelid = 'public.notas_lideres'::regclass
    AND c.contype = 'p'
  GROUP BY c.conname;

  IF pk_name IS NOT NULL AND pk_cols = ARRAY['miembro_id']::text[] THEN
    EXECUTE format('ALTER TABLE public.notas_lideres DROP CONSTRAINT %I', pk_name);
  END IF;
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS notas_lideres_miembro_lider_uidx
  ON public.notas_lideres(miembro_id, lider_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.notas_lideres'::regclass
      AND conname = 'notas_lideres_lider_id_fkey'
  ) THEN
    ALTER TABLE public.notas_lideres
      ADD CONSTRAINT notas_lideres_lider_id_fkey
      FOREIGN KEY (lider_id) REFERENCES auth.users(id) ON DELETE CASCADE;
  END IF;
END;
$$;

ALTER TABLE public.notas_lideres ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE p record;
BEGIN
  FOR p IN SELECT policyname FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'notas_lideres'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.notas_lideres', p.policyname);
  END LOOP;
END;
$$;

CREATE POLICY notas_lideres_select_privado
ON public.notas_lideres FOR SELECT TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = auth.uid())
);

CREATE POLICY notas_lideres_insert_privado
ON public.notas_lideres FOR INSERT TO authenticated
WITH CHECK (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = auth.uid())
);

CREATE POLICY notas_lideres_update_privado
ON public.notas_lideres FOR UPDATE TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = auth.uid())
)
WITH CHECK (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = auth.uid())
);

CREATE POLICY notas_lideres_delete_privado
ON public.notas_lideres FOR DELETE TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = auth.uid())
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.notas_lideres TO authenticated;
REVOKE ALL ON public.notas_lideres FROM anon;

COMMIT;
