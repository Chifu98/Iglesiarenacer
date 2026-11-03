-- Iglesia Renacer: agregar el rol Líder con permisos equivalentes a Escritura.
-- Ejecutar UNA SOLA VEZ en Supabase SQL Editor.

BEGIN;

ALTER TABLE public.perfiles_app
  DROP CONSTRAINT IF EXISTS perfiles_app_roles_check;

ALTER TABLE public.perfiles_app
  ADD CONSTRAINT perfiles_app_roles_check
  CHECK (
    cardinality(roles) BETWEEN 1 AND 2
    AND roles @> ARRAY['hermano']::text[]
    AND roles[1] = 'hermano'
    AND (
      cardinality(roles) = 1
      OR roles[2] IN ('admin','escritura','lectura','pastor','servidor','lider')
    )
  );

CREATE OR REPLACE FUNCTION public.app_tiene_rol(p_rol text)
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
      AND (
        p.roles @> ARRAY[p_rol]::text[]
        OR (
          p_rol = 'escritura'
          AND p.roles && ARRAY['pastor','servidor','lider']::text[]
        )
      )
  );
$$;

REVOKE ALL ON FUNCTION public.app_tiene_rol(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.app_tiene_rol(text) TO authenticated;

CREATE OR REPLACE FUNCTION public.app_rol_actual()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN p.roles @> ARRAY['admin']::text[] THEN 'admin'
    WHEN p.roles && ARRAY['escritura','pastor','servidor','lider']::text[] THEN 'escritura'
    WHEN p.roles @> ARRAY['lectura']::text[] THEN 'lectura'
    ELSE 'hermano'
  END
  FROM public.perfiles_app p
  WHERE p.id = auth.uid()
    AND p.activo = TRUE
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.sincronizar_roles_perfil_renacer()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_roles text[];
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.roles IS NULL OR NEW.roles = ARRAY['hermano']::text[] THEN
      IF NEW.rol = 'hermano' THEN
        v_roles := ARRAY['hermano']::text[];
      ELSE
        v_roles := ARRAY['hermano', NEW.rol]::text[];
      END IF;
    ELSE
      v_roles := NEW.roles;
    END IF;
  ELSIF NEW.roles IS DISTINCT FROM OLD.roles THEN
    v_roles := NEW.roles;
  ELSIF NEW.rol IS DISTINCT FROM OLD.rol THEN
    IF NEW.rol = 'hermano' THEN
      v_roles := ARRAY['hermano']::text[];
    ELSE
      v_roles := ARRAY['hermano', NEW.rol]::text[];
    END IF;
  ELSE
    v_roles := NEW.roles;
  END IF;

  IF v_roles IS NULL
     OR NOT (v_roles @> ARRAY['hermano']::text[])
     OR cardinality(v_roles) < 1
     OR cardinality(v_roles) > 2
     OR EXISTS (
       SELECT 1 FROM unnest(v_roles) r
       WHERE r NOT IN ('hermano','admin','escritura','lectura','pastor','servidor','lider')
     )
     OR cardinality(v_roles) <> cardinality(ARRAY(SELECT DISTINCT unnest(v_roles))) THEN
    RAISE EXCEPTION 'Roles no válidos. Todo perfil debe tener Miembro y como máximo un rol adicional.';
  END IF;

  NEW.roles := ARRAY['hermano']::text[] ||
    ARRAY(
      SELECT r
      FROM unnest(v_roles) r
      WHERE r <> 'hermano'
      ORDER BY CASE r
        WHEN 'admin' THEN 1
        WHEN 'escritura' THEN 2
        WHEN 'pastor' THEN 3
        WHEN 'servidor' THEN 4
        WHEN 'lider' THEN 5
        WHEN 'lectura' THEN 6
        ELSE 7
      END
    );

  NEW.rol := CASE
    WHEN NEW.roles @> ARRAY['admin']::text[] THEN 'admin'
    WHEN NEW.roles && ARRAY['escritura','pastor','servidor','lider']::text[] THEN 'escritura'
    WHEN NEW.roles @> ARRAY['lectura']::text[] THEN 'lectura'
    ELSE 'hermano'
  END;

  RETURN NEW;
END;
$$;

COMMIT;
