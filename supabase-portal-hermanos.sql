-- IGLESIA RENACER: Portal privado de hermanos y avisos congregacionales
-- Ejecutar UNA VEZ en Supabase > SQL Editor antes de probar el nuevo portal.
-- Requiere las tablas existentes perfiles_app, miembros_app, peticiones_oracion
-- y la función public.app_rol_actual().

BEGIN;

-- Vinculación segura entre una cuenta de Auth y un único miembro oficial.
ALTER TABLE public.perfiles_app
  ADD COLUMN IF NOT EXISTS miembro_id TEXT;

DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'public.perfiles_app'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) ILIKE '%rol%'
  LOOP
    EXECUTE format('ALTER TABLE public.perfiles_app DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;

ALTER TABLE public.perfiles_app
  ADD CONSTRAINT perfiles_app_rol_portal_check
  CHECK (rol IN ('admin', 'escritura', 'lectura', 'hermano'));

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.perfiles_app'::regclass
      AND conname = 'perfiles_app_miembro_id_fkey'
  ) THEN
    ALTER TABLE public.perfiles_app
      ADD CONSTRAINT perfiles_app_miembro_id_fkey
      FOREIGN KEY (miembro_id) REFERENCES public.miembros_app(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS perfiles_app_miembro_id_unico
  ON public.perfiles_app (miembro_id)
  WHERE miembro_id IS NOT NULL;

-- Una cuenta de hermano solo se crea si su correo coincide con un miembro
-- activo ya aprobado e incorporado a miembros_app.
CREATE OR REPLACE FUNCTION public.crear_perfil_pendiente_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  nombre_usuario TEXT;
  rol_solicitado TEXT;
  miembro_encontrado TEXT;
  cantidad INTEGER;
BEGIN
  nombre_usuario := COALESCE(
    NULLIF(trim(NEW.raw_user_meta_data ->> 'nombre'), ''),
    split_part(COALESCE(NEW.email, ''), '@', 1),
    'Usuario'
  );

  rol_solicitado := CASE
    WHEN NEW.raw_user_meta_data ->> 'tipo_cuenta' = 'hermano' THEN 'hermano'
    ELSE 'lectura'
  END;

  IF rol_solicitado = 'hermano' THEN
    SELECT COUNT(*), MIN(id)
      INTO cantidad, miembro_encontrado
    FROM public.miembros_app
    WHERE lower(trim(email)) = lower(trim(NEW.email))
      AND status = 'Activo';

    IF cantidad <> 1 THEN
      RAISE EXCEPTION 'El correo debe coincidir con un único perfil congregacional activo.';
    END IF;

    SELECT name INTO nombre_usuario
    FROM public.miembros_app
    WHERE id = miembro_encontrado;

    IF EXISTS (
      SELECT 1 FROM public.perfiles_app
      WHERE miembro_id = miembro_encontrado
    ) THEN
      RAISE EXCEPTION 'Este perfil congregacional ya tiene una cuenta vinculada.';
    END IF;

    INSERT INTO public.perfiles_app
      (id, nombre, usuario, rol, activo, estado_solicitud, miembro_id)
    VALUES
      (NEW.id, nombre_usuario, lower(NEW.email), 'hermano', false, 'pendiente', miembro_encontrado)
    ON CONFLICT (id) DO NOTHING;
  ELSE
    INSERT INTO public.perfiles_app
      (id, nombre, usuario, rol, activo, estado_solicitud)
    VALUES
      (NEW.id, nombre_usuario, lower(NEW.email), 'lectura', false, 'pendiente')
    ON CONFLICT (id) DO NOTHING;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS crear_perfil_pendiente_renacer ON auth.users;
CREATE TRIGGER crear_perfil_pendiente_renacer
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.crear_perfil_pendiente_renacer();

-- Función auxiliar SECURITY DEFINER para obtener el ID propio sin recursión RLS.
CREATE OR REPLACE FUNCTION public.app_miembro_id_actual()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT miembro_id
  FROM public.perfiles_app
  WHERE id = auth.uid() AND activo = TRUE AND rol = 'hermano'
  LIMIT 1;
$$;

REVOKE ALL ON FUNCTION public.app_miembro_id_actual() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.app_miembro_id_actual() TO authenticated;

-- Miembros: los roles internos conservan su alcance y el hermano solo ve su ficha.
DROP POLICY IF EXISTS miembros_select_roles ON public.miembros_app;
CREATE POLICY miembros_select_roles
ON public.miembros_app
FOR SELECT TO authenticated
USING (
  public.app_rol_actual() IN ('admin', 'escritura', 'lectura')
  OR (
    public.app_rol_actual() = 'hermano'
    AND id = public.app_miembro_id_actual()
  )
);

-- Peticiones: los hermanos solo pueden consultar y crear las propias.
DROP POLICY IF EXISTS peticiones_select_roles ON public.peticiones_oracion;
CREATE POLICY peticiones_select_roles
ON public.peticiones_oracion
FOR SELECT TO authenticated
USING (
  public.app_rol_actual() IN ('admin', 'escritura', 'lectura')
  OR (
    public.app_rol_actual() = 'hermano'
    AND member_id = public.app_miembro_id_actual()
  )
);

DROP POLICY IF EXISTS peticiones_insert_roles ON public.peticiones_oracion;
CREATE POLICY peticiones_insert_roles
ON public.peticiones_oracion
FOR INSERT TO authenticated
WITH CHECK (
  public.app_rol_actual() IN ('admin', 'escritura', 'lectura')
  OR (
    public.app_rol_actual() = 'hermano'
    AND member_id = public.app_miembro_id_actual()
    AND created_by = auth.uid()
  )
);

-- Tabla de avisos.
CREATE TABLE IF NOT EXISTS public.avisos_congregacion (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL CHECK (char_length(btrim(title)) BETWEEN 3 AND 120),
  body TEXT NOT NULL CHECK (char_length(btrim(body)) BETWEEN 3 AND 5000),
  published BOOLEAN NOT NULL DEFAULT FALSE,
  created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  published_at TIMESTAMPTZ
);

ALTER TABLE public.avisos_congregacion ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.avisos_congregacion FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.avisos_congregacion TO authenticated;

DROP POLICY IF EXISTS avisos_select_publicados_o_admin ON public.avisos_congregacion;
CREATE POLICY avisos_select_publicados_o_admin
ON public.avisos_congregacion
FOR SELECT TO authenticated
USING (
  public.app_rol_actual() IN ('admin', 'escritura', 'lectura', 'hermano')
  AND (published = TRUE OR public.app_rol_actual() = 'admin')
);

DROP POLICY IF EXISTS avisos_insert_admin ON public.avisos_congregacion;
CREATE POLICY avisos_insert_admin
ON public.avisos_congregacion
FOR INSERT TO authenticated
WITH CHECK (
  public.app_rol_actual() = 'admin'
  AND created_by = auth.uid()
);

DROP POLICY IF EXISTS avisos_update_admin ON public.avisos_congregacion;
CREATE POLICY avisos_update_admin
ON public.avisos_congregacion
FOR UPDATE TO authenticated
USING (public.app_rol_actual() = 'admin')
WITH CHECK (public.app_rol_actual() = 'admin');

DROP POLICY IF EXISTS avisos_delete_admin ON public.avisos_congregacion;
CREATE POLICY avisos_delete_admin
ON public.avisos_congregacion
FOR DELETE TO authenticated
USING (public.app_rol_actual() = 'admin');

-- Cumpleaños: se devuelve exclusivamente nombre y fecha, no otros datos personales.
CREATE OR REPLACE FUNCTION public.listar_cumpleanos_congregacion()
RETURNS TABLE(nombre TEXT, cumpleanos DATE)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF auth.uid() IS NULL OR public.app_rol_actual() <> 'hermano' THEN
    RAISE EXCEPTION 'Solo los hermanos con acceso aprobado pueden consultar los cumpleaños.';
  END IF;

  RETURN QUERY
  SELECT m.name, m.birthday
  FROM public.miembros_app AS m
  WHERE m.status = 'Activo'
    AND m.birthday IS NOT NULL
  ORDER BY EXTRACT(MONTH FROM m.birthday), EXTRACT(DAY FROM m.birthday), m.name;
END;
$$;

REVOKE ALL ON FUNCTION public.listar_cumpleanos_congregacion() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.listar_cumpleanos_congregacion() TO authenticated;

-- Habilitar avisos en Realtime si aún no están publicados.
DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE public.avisos_congregacion;
EXCEPTION
  WHEN duplicate_object THEN NULL;
  WHEN undefined_object THEN NULL;
END $$;

COMMIT;

-- Verificación:
SELECT id, nombre, usuario, rol, activo, estado_solicitud, miembro_id
FROM public.perfiles_app
ORDER BY nombre;

SELECT id, title, published, created_at
FROM public.avisos_congregacion
ORDER BY created_at DESC;
