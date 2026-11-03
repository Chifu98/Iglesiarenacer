-- Renacer: Pastor absorbe permisos de Escritura; se eliminan Lectura y Escritura.
BEGIN;

-- Convertir asignaciones antiguas antes de restringir el catálogo:
-- Escritura -> Pastor (conserva la capacidad de gestión).
-- Lectura -> Hermano (mínimo acceso personal, sin ampliar privilegios).
UPDATE public.perfiles_app p
SET roles = (
  SELECT array_agg(role_name ORDER BY CASE role_name
    WHEN 'admin' THEN 1
    WHEN 'pastor' THEN 2
    WHEN 'lider' THEN 3
    WHEN 'servidor' THEN 4
    WHEN 'hermano' THEN 5
    ELSE 6
  END)
  FROM (
    SELECT DISTINCT CASE old_role
      WHEN 'escritura' THEN 'pastor'
      WHEN 'lectura' THEN 'hermano'
      ELSE old_role
    END AS role_name
    FROM unnest(COALESCE(p.roles, ARRAY[COALESCE(p.rol, 'hermano')]::text[])) AS old_role
  ) normalized
)
WHERE p.roles && ARRAY['escritura','lectura']::text[]
   OR p.rol IN ('escritura','lectura');

-- Catálogo definitivo: admin, pastor, lider, servidor y hermano.
CREATE OR REPLACE FUNCTION public.app_roles_valid(p_roles text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $$
  SELECT p_roles IS NOT NULL
    AND cardinality(p_roles) BETWEEN 1 AND 5
    AND p_roles <@ ARRAY['admin','pastor','lider','servidor','hermano']::text[]
    AND cardinality(p_roles) = (
      SELECT COUNT(DISTINCT role_name)::integer
      FROM unnest(p_roles) AS role_name
    );
$$;

-- Normalizar cualquier dato legacy que llegue por la columna rol o por roles[].
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
    v_roles := ARRAY[COALESCE(NEW.rol, 'hermano')]::text[];
  ELSE
    v_roles := NEW.roles;
  END IF;

  SELECT array_agg(role_name ORDER BY CASE role_name
    WHEN 'admin' THEN 1
    WHEN 'pastor' THEN 2
    WHEN 'lider' THEN 3
    WHEN 'servidor' THEN 4
    WHEN 'hermano' THEN 5
    ELSE 6
  END)
  INTO v_roles
  FROM (
    SELECT DISTINCT CASE old_role
      WHEN 'escritura' THEN 'pastor'
      WHEN 'lectura' THEN 'hermano'
      ELSE old_role
    END AS role_name
    FROM unnest(COALESCE(v_roles, ARRAY[]::text[])) AS old_role
  ) normalized;

  IF v_roles IS NULL OR cardinality(v_roles) < 1 OR cardinality(v_roles) > 5
     OR EXISTS (
       SELECT 1 FROM unnest(v_roles) AS role_name
       WHERE role_name NOT IN ('admin','pastor','lider','servidor','hermano')
     ) THEN
    RAISE EXCEPTION 'Roles no válidos. Selecciona uno o más roles disponibles.';
  END IF;

  NEW.roles := v_roles;
  NEW.rol := v_roles[1];
  RETURN NEW;
END;
$$;

-- Pastor toma todas las capacidades de gestión que antes pertenecían a Escritura.
CREATE OR REPLACE FUNCTION public.app_puede_gestionar_anuncios()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor');
$$;

-- Directorio legado public.miembros.
DROP POLICY IF EXISTS miembros_select_autorizados ON public.miembros;
DROP POLICY IF EXISTS miembros_insert_gestores ON public.miembros;
DROP POLICY IF EXISTS miembros_update_gestores ON public.miembros;
DROP POLICY IF EXISTS miembros_delete_gestores ON public.miembros;

CREATE POLICY miembros_select_autorizados
ON public.miembros FOR SELECT TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

CREATE POLICY miembros_insert_gestores
ON public.miembros FOR INSERT TO authenticated
WITH CHECK (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

CREATE POLICY miembros_update_gestores
ON public.miembros FOR UPDATE TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
)
WITH CHECK (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

CREATE POLICY miembros_delete_gestores
ON public.miembros FOR DELETE TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

-- Directorio activo: Pastor puede gestionar; Hermano conserva solo su propio registro.
DROP POLICY IF EXISTS miembros_app_select_privacidad ON public.miembros_app;
DROP POLICY IF EXISTS miembros_app_insert_gestores ON public.miembros_app;
DROP POLICY IF EXISTS miembros_app_update_gestores ON public.miembros_app;
DROP POLICY IF EXISTS miembros_app_delete_gestores ON public.miembros_app;

CREATE POLICY miembros_app_select_privacidad
ON public.miembros_app FOR SELECT TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
  OR (
    public.app_tiene_rol_exacto('hermano')
    AND id = public.app_miembro_id_actual()
  )
);

CREATE POLICY miembros_app_insert_gestores
ON public.miembros_app FOR INSERT TO authenticated
WITH CHECK (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

CREATE POLICY miembros_app_update_gestores
ON public.miembros_app FOR UPDATE TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
)
WITH CHECK (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

CREATE POLICY miembros_app_delete_gestores
ON public.miembros_app FOR DELETE TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

-- Peticiones: Pastor asume las operaciones que antes tenía Escritura.
DROP POLICY IF EXISTS peticiones_select_privacidad ON public.peticiones_oracion;
DROP POLICY IF EXISTS peticiones_insert_propias ON public.peticiones_oracion;
DROP POLICY IF EXISTS peticiones_update_gestores ON public.peticiones_oracion;
DROP POLICY IF EXISTS peticiones_delete_gestores ON public.peticiones_oracion;

CREATE POLICY peticiones_select_privacidad
ON public.peticiones_oracion FOR SELECT TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
  OR (
    created_by = (SELECT auth.uid())
    AND member_id = public.app_miembro_id_actual()
  )
);

CREATE POLICY peticiones_insert_propias
ON public.peticiones_oracion FOR INSERT TO authenticated
WITH CHECK (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
  OR (
    member_id = public.app_miembro_id_actual()
    AND created_by = (SELECT auth.uid())
  )
);

CREATE POLICY peticiones_update_gestores
ON public.peticiones_oracion FOR UPDATE TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
)
WITH CHECK (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

CREATE POLICY peticiones_delete_gestores
ON public.peticiones_oracion FOR DELETE TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
);

COMMIT;
