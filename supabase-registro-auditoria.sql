-- Iglesia Renacer: auditoría de actividad.
-- Ejecutar en Supabase SQL Editor después de desplegar el cambio de interfaz.
-- Registra quién, cuándo, qué tabla y qué campos fueron afectados.
-- No copia valores personales ni contenido de notas pastorales.

CREATE TABLE IF NOT EXISTS public.registro_auditoria (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  actor_id uuid NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  actor_name text NOT NULL DEFAULT 'Sistema',
  actor_role text NOT NULL DEFAULT 'sistema',
  action text NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
  entity_table text NOT NULL,
  entity_id text,
  changed_fields text[] NOT NULL DEFAULT ARRAY[]::text[]
);

CREATE INDEX IF NOT EXISTS idx_registro_auditoria_created_at
  ON public.registro_auditoria (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_registro_auditoria_actor_id
  ON public.registro_auditoria (actor_id);
CREATE INDEX IF NOT EXISTS idx_registro_auditoria_entity
  ON public.registro_auditoria (entity_table, entity_id);

ALTER TABLE public.registro_auditoria ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.registro_auditoria FROM anon, authenticated;
GRANT SELECT ON public.registro_auditoria TO authenticated;

DROP POLICY IF EXISTS registro_auditoria_select_admin ON public.registro_auditoria;
CREATE POLICY registro_auditoria_select_admin
ON public.registro_auditoria
FOR SELECT
TO authenticated
USING (public.app_rol_actual() = 'admin');

CREATE OR REPLACE FUNCTION public.registrar_evento_auditoria_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
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
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    v_old := to_jsonb(OLD);
  END IF;

  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    v_new := to_jsonb(NEW);
  END IF;

  -- No generar ruido cuando la aplicación solo actualiza updated_at.
  IF TG_OP = 'UPDATE'
     AND (v_old - 'updated_at') = (v_new - 'updated_at') THEN
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
    SELECT COALESCE(nombre, 'Usuario'), COALESCE(rol, 'sin_rol')
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
  )
  VALUES (
    v_actor_id, v_actor_name, v_actor_role, TG_OP, TG_TABLE_NAME, v_entity_id, v_changed_fields
  );

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS auditoria_miembros_app ON public.miembros_app;
CREATE TRIGGER auditoria_miembros_app
AFTER INSERT OR UPDATE OR DELETE ON public.miembros_app
FOR EACH ROW EXECUTE FUNCTION public.registrar_evento_auditoria_renacer();

DROP TRIGGER IF EXISTS auditoria_peticiones_oracion ON public.peticiones_oracion;
CREATE TRIGGER auditoria_peticiones_oracion
AFTER INSERT OR UPDATE OR DELETE ON public.peticiones_oracion
FOR EACH ROW EXECUTE FUNCTION public.registrar_evento_auditoria_renacer();

DROP TRIGGER IF EXISTS auditoria_perfiles_app ON public.perfiles_app;
CREATE TRIGGER auditoria_perfiles_app
AFTER INSERT OR UPDATE OR DELETE ON public.perfiles_app
FOR EACH ROW EXECUTE FUNCTION public.registrar_evento_auditoria_renacer();

DROP TRIGGER IF EXISTS auditoria_notas_pastorales ON public.notas_pastorales;
CREATE TRIGGER auditoria_notas_pastorales
AFTER INSERT OR UPDATE OR DELETE ON public.notas_pastorales
FOR EACH ROW EXECUTE FUNCTION public.registrar_evento_auditoria_renacer();

-- Verificación: deben aparecer cuatro triggers y la política de lectura exclusiva admin.
SELECT event_object_table, trigger_name
FROM information_schema.triggers
WHERE trigger_schema = 'public'
  AND trigger_name IN (
    'auditoria_miembros_app',
    'auditoria_peticiones_oracion',
    'auditoria_perfiles_app',
    'auditoria_notas_pastorales'
  )
ORDER BY event_object_table;

SELECT policyname, cmd, roles
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename = 'registro_auditoria';
