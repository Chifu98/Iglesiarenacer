-- Iglesia Renacer: migración segura a roles múltiples.
-- Ejecutar UNA SOLA VEZ en Supabase SQL Editor después de respaldar la base de datos.
-- Conserva perfiles_app.rol temporalmente como columna de compatibilidad.

BEGIN;

-- 1) Nueva columna y conversión de los roles existentes.
ALTER TABLE public.perfiles_app
  ADD COLUMN IF NOT EXISTS roles text[];

UPDATE public.perfiles_app
SET roles = CASE
  WHEN rol = 'hermano' THEN ARRAY['hermano']::text[]
  ELSE ARRAY['hermano', rol]::text[]
END
WHERE roles IS NULL;

ALTER TABLE public.perfiles_app
  ALTER COLUMN roles SET DEFAULT ARRAY['hermano']::text[],
  ALTER COLUMN roles SET NOT NULL;

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
      OR roles[2] IN ('admin','escritura','lectura')
    )
  );

-- 2) Helper para verificar roles de forma explícita.
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
      AND p.roles @> ARRAY[p_rol]::text[]
  );
$$;

REVOKE ALL ON FUNCTION public.app_tiene_rol(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.app_tiene_rol(text) TO authenticated;

-- 3) Compatibilidad temporal: políticas RLS antiguas siguen usando app_rol_actual().
-- Precedencia: admin > escritura > lectura > hermano.
CREATE OR REPLACE FUNCTION public.app_rol_actual()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT CASE
    WHEN p.roles @> ARRAY['admin']::text[] THEN 'admin'
    WHEN p.roles @> ARRAY['escritura']::text[] THEN 'escritura'
    WHEN p.roles @> ARRAY['lectura']::text[] THEN 'lectura'
    ELSE 'hermano'
  END
  FROM public.perfiles_app p
  WHERE p.id = auth.uid()
    AND p.activo = TRUE
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.app_miembro_id_actual()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT miembro_id
  FROM public.perfiles_app
  WHERE id = auth.uid()
    AND activo = TRUE
    AND roles @> ARRAY['hermano']::text[]
  LIMIT 1;
$$;

-- 4) Mantener sincronizada la columna rol antigua y normalizar el arreglo.
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
       WHERE r NOT IN ('hermano','admin','escritura','lectura')
     )
     OR cardinality(v_roles) <> cardinality(ARRAY(SELECT DISTINCT unnest(v_roles))) THEN
    RAISE EXCEPTION 'Roles no válidos. Todo perfil debe tener hermano y como máximo un rol adicional.';
  END IF;

  -- Orden canónico para que las comparaciones y la interfaz sean estables.
  NEW.roles := ARRAY['hermano']::text[] ||
    ARRAY(
      SELECT r
      FROM unnest(v_roles) r
      WHERE r <> 'hermano'
      ORDER BY CASE r WHEN 'admin' THEN 1 WHEN 'escritura' THEN 2 WHEN 'lectura' THEN 3 ELSE 4 END
    );

  NEW.rol := CASE
    WHEN NEW.roles @> ARRAY['admin']::text[] THEN 'admin'
    WHEN NEW.roles @> ARRAY['escritura']::text[] THEN 'escritura'
    WHEN NEW.roles @> ARRAY['lectura']::text[] THEN 'lectura'
    ELSE 'hermano'
  END;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS perfiles_app_sincronizar_roles ON public.perfiles_app;
CREATE TRIGGER perfiles_app_sincronizar_roles
BEFORE INSERT OR UPDATE OF roles, rol
ON public.perfiles_app
FOR EACH ROW
EXECUTE FUNCTION public.sincronizar_roles_perfil_renacer();

-- 5) Protección del último administrador usando roles.
CREATE OR REPLACE FUNCTION public.proteger_ultimo_admin_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  otros_admins_activos integer;
BEGIN
  IF OLD.roles @> ARRAY['admin']::text[]
     AND OLD.activo = TRUE
     AND (
       NOT (NEW.roles @> ARRAY['admin']::text[])
       OR NEW.activo = FALSE
     ) THEN
    SELECT COUNT(*) INTO otros_admins_activos
    FROM public.perfiles_app
    WHERE roles @> ARRAY['admin']::text[]
      AND activo = TRUE
      AND id <> OLD.id;

    IF otros_admins_activos = 0 THEN
      RAISE EXCEPTION 'No se puede quitar o desactivar al último administrador activo.';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS proteger_ultimo_admin_renacer ON public.perfiles_app;
CREATE TRIGGER proteger_ultimo_admin_renacer
BEFORE UPDATE OF roles, rol, activo
ON public.perfiles_app
FOR EACH ROW
EXECUTE FUNCTION public.proteger_ultimo_admin_renacer();

-- 6) Registro de auditoría: guardar la lista de roles del actor.
CREATE OR REPLACE FUNCTION public.registrar_evento_auditoria_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_old jsonb := '{}'::jsonb;
  v_new jsonb := '{}'::jsonb;
  v_actor_id uuid;
  v_actor_name text;
  v_actor_role text;
  v_entity_id text;
  v_changed_fields text[];
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') THEN v_old := to_jsonb(OLD); END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN v_new := to_jsonb(NEW); END IF;

  IF TG_OP = 'UPDATE' AND (v_old - 'updated_at') = (v_new - 'updated_at') THEN
    RETURN NEW;
  END IF;

  SELECT COALESCE(array_agg(changed.key ORDER BY changed.key), ARRAY[]::text[])
  INTO v_changed_fields
  FROM (
    SELECT COALESCE(n.key, o.key) AS key
    FROM jsonb_each(v_new) AS n
    FULL JOIN jsonb_each(v_old) AS o USING (key)
    WHERE n.value IS DISTINCT FROM o.value
  ) AS changed;

  v_actor_id := auth.uid();
  v_actor_name := 'Sistema';
  v_actor_role := 'sistema';

  IF v_actor_id IS NOT NULL THEN
    SELECT COALESCE(nombre, 'Usuario'),
           COALESCE(array_to_string(roles, ','), rol, 'sin_rol')
    INTO v_actor_name, v_actor_role
    FROM public.perfiles_app
    WHERE id = v_actor_id;
    v_actor_name := COALESCE(v_actor_name, 'Usuario');
    v_actor_role := COALESCE(v_actor_role, 'sin_rol');
  END IF;

  IF TG_OP = 'DELETE' THEN
    v_entity_id := COALESCE(v_old ->> 'id', v_old ->> 'miembro_id');
  ELSE
    v_entity_id := COALESCE(v_new ->> 'id', v_new ->> 'miembro_id');
  END IF;

  INSERT INTO public.registro_auditoria (
    actor_id, actor_name, actor_role, action, entity_table, entity_id, changed_fields
  ) VALUES (
    v_actor_id, v_actor_name, v_actor_role, TG_OP, TG_TABLE_NAME, v_entity_id, v_changed_fields
  );

  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

-- 7) Aprobación de solicitudes: requiere el rol admin dentro del arreglo.
CREATE OR REPLACE FUNCTION public.aprobar_solicitud_registro_miembro(p_solicitud_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_solicitud public.solicitudes_registro_miembros%ROWTYPE;
  v_nuevo_miembro_id text;
  v_perfil_id uuid;
BEGIN
  IF auth.uid() IS NULL OR NOT public.app_tiene_rol('admin') THEN
    RAISE EXCEPTION 'Solo un administrador puede aprobar solicitudes';
  END IF;

  SELECT * INTO v_solicitud
  FROM public.solicitudes_registro_miembros
  WHERE id = p_solicitud_id
  FOR UPDATE;

  IF NOT FOUND THEN RAISE EXCEPTION 'Solicitud no encontrada'; END IF;
  IF v_solicitud.estado_solicitud <> 'pendiente' THEN
    RAISE EXCEPTION 'La solicitud ya fue revisada';
  END IF;
  IF v_solicitud.email IS NULL OR v_solicitud.auth_user_id IS NULL THEN
    RAISE EXCEPTION 'La solicitud no tiene una cuenta Auth vinculada';
  END IF;

  SELECT id INTO v_perfil_id
  FROM public.perfiles_app
  WHERE id = v_solicitud.auth_user_id
    AND roles @> ARRAY['hermano']::text[]
    AND activo = FALSE
    AND estado_solicitud = 'pendiente'
    AND miembro_id IS NULL
  FOR UPDATE;

  IF v_perfil_id IS NULL THEN
    RAISE EXCEPTION 'No existe un perfil de hermano pendiente válido';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.miembros_app
    WHERE LOWER(email) = LOWER(v_solicitud.email)
  ) THEN
    RAISE EXCEPTION 'Ya existe un miembro con este correo electrónico';
  END IF;

  v_nuevo_miembro_id := gen_random_uuid()::text;

  INSERT INTO public.miembros_app (
    id, name, phone, email, address, marital_status, spouse_type,
    spouse_name, spouse_id, ministry, status, baptized, birthday
  ) VALUES (
    v_nuevo_miembro_id, v_solicitud.name, v_solicitud.phone,
    LOWER(v_solicitud.email), v_solicitud.address,
    v_solicitud.marital_status, v_solicitud.spouse_type,
    v_solicitud.spouse_name, v_solicitud.spouse_id,
    v_solicitud.ministry, v_solicitud.status,
    v_solicitud.baptized, v_solicitud.birthday
  );

  UPDATE public.perfiles_app
  SET miembro_id = v_nuevo_miembro_id,
      activo = TRUE,
      estado_solicitud = 'aprobado',
      nombre = v_solicitud.name
  WHERE id = v_perfil_id;

  UPDATE public.solicitudes_registro_miembros
  SET estado_solicitud = 'aprobado',
      reviewed_at = now(),
      reviewed_by = auth.uid()
  WHERE id = p_solicitud_id;

  RETURN v_nuevo_miembro_id;
END;
$$;

REVOKE ALL ON FUNCTION public.aprobar_solicitud_registro_miembro(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.aprobar_solicitud_registro_miembro(uuid) TO authenticated;

-- 8) Nuevas cuentas públicas: siempre hermano y pendientes de aprobación.
CREATE OR REPLACE FUNCTION public.crear_perfil_pendiente_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_solicitud_id uuid;
  v_solicitud public.solicitudes_registro_miembros%ROWTYPE;
BEGIN
  IF COALESCE(NEW.raw_user_meta_data ->> 'tipo_cuenta', '') <> 'hermano' THEN
    RAISE EXCEPTION 'El registro público solo permite cuentas de hermanos.';
  END IF;

  BEGIN
    v_solicitud_id := (NEW.raw_user_meta_data ->> 'solicitud_id')::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'Solicitud de incorporación no válida';
  END;

  SELECT * INTO v_solicitud
  FROM public.solicitudes_registro_miembros
  WHERE id = v_solicitud_id
  FOR UPDATE;

  IF NOT FOUND
     OR v_solicitud.estado_solicitud <> 'pendiente'
     OR LOWER(BTRIM(v_solicitud.email)) <> LOWER(BTRIM(NEW.email)) THEN
    RAISE EXCEPTION 'No existe una solicitud pendiente válida para este correo';
  END IF;

  IF v_solicitud.auth_user_id IS NOT NULL THEN
    RAISE EXCEPTION 'La solicitud ya tiene una cuenta asociada';
  END IF;

  IF EXISTS (SELECT 1 FROM public.miembros_app WHERE LOWER(email) = LOWER(NEW.email)) THEN
    RAISE EXCEPTION 'Este correo ya está asociado a un miembro registrado';
  END IF;

  IF EXISTS (SELECT 1 FROM public.perfiles_app WHERE LOWER(usuario) = LOWER(NEW.email)) THEN
    RAISE EXCEPTION 'Este correo ya tiene un perfil en la aplicación';
  END IF;

  INSERT INTO public.perfiles_app
    (id, nombre, usuario, rol, roles, activo, estado_solicitud, miembro_id)
  VALUES
    (NEW.id, v_solicitud.name, LOWER(NEW.email), 'hermano',
     ARRAY['hermano']::text[], FALSE, 'pendiente', NULL)
  ON CONFLICT (id) DO NOTHING;

  UPDATE public.solicitudes_registro_miembros
  SET auth_user_id = NEW.id
  WHERE id = v_solicitud_id;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.crear_perfil_pendiente_renacer() FROM PUBLIC, anon, authenticated;

-- 9) Cumpleaños: cualquier cuenta que incluya hermano puede consultarlos.
CREATE OR REPLACE FUNCTION public.listar_cumpleanos_congregacion()
RETURNS TABLE(nombre text, cumpleanos text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF auth.uid() IS NULL OR NOT public.app_tiene_rol('hermano') THEN
    RAISE EXCEPTION 'Solo los hermanos con acceso aprobado pueden consultar los cumpleaños.';
  END IF;

  RETURN QUERY
  SELECT m.name, to_char(m.birthday, 'DD/MM')
  FROM public.miembros_app AS m
  WHERE m.status = 'Activo'
    AND m.birthday IS NOT NULL
  ORDER BY EXTRACT(MONTH FROM m.birthday), EXTRACT(DAY FROM m.birthday), m.name;
END;
$$;

-- 10) INSERT de peticiones: admin/escritura pueden registrar para otros;
-- hermano+lectura y hermano simple quedan limitados a su propio miembro.
DROP POLICY IF EXISTS peticiones_insert_roles ON public.peticiones_oracion;
CREATE POLICY peticiones_insert_roles
ON public.peticiones_oracion
FOR INSERT
TO authenticated
WITH CHECK (
  (
    public.app_tiene_rol('admin')
    OR public.app_tiene_rol('escritura')
  )
  OR (
    member_id = public.app_miembro_id_actual()
    AND created_by = auth.uid()
  )
);

COMMIT;
