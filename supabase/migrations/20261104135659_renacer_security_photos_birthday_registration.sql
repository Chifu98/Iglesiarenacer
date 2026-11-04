-- Cumpleaños visibles para miembros activos, sin exponer el directorio completo.
CREATE OR REPLACE FUNCTION public.listar_cumpleanos_congregacion()
RETURNS TABLE(nombre text, cumpleanos text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $function$
BEGIN
  IF auth.uid() IS NULL OR NOT public.app_perfil_activo()
     OR NOT public.app_tiene_rol_exacto('miembro') THEN
    RAISE EXCEPTION 'Solo los miembros con acceso aprobado pueden consultar los cumpleaños.';
  END IF;
  RETURN QUERY
  SELECT m.name, to_char(m.birthday, 'YYYY-MM-DD')
  FROM public.miembros_app AS m
  WHERE m.status = 'Activo' AND m.birthday IS NOT NULL
  ORDER BY EXTRACT(MONTH FROM m.birthday), EXTRACT(DAY FROM m.birthday), m.name;
END;
$function$;
REVOKE ALL ON FUNCTION public.listar_cumpleanos_congregacion() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.listar_cumpleanos_congregacion() TO authenticated;

-- Limitación de intentos de registro público: 3 intentos por correo cada hora.
CREATE TABLE IF NOT EXISTS public.registro_publico_intentos (
  email text PRIMARY KEY,
  window_started_at timestamptz NOT NULL DEFAULT now(),
  attempts integer NOT NULL DEFAULT 0
);
ALTER TABLE public.registro_publico_intentos ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.registro_publico_intentos FROM PUBLIC, anon, authenticated;
CREATE UNIQUE INDEX IF NOT EXISTS solicitudes_registro_email_pendiente_uidx
  ON public.solicitudes_registro_miembros (lower(email))
  WHERE estado_solicitud = 'pendiente';

CREATE OR REPLACE FUNCTION public.crear_solicitud_registro_miembro(
  p_name text,p_phone text,p_email text,p_address text,p_marital_status text,
  p_spouse_type text,p_spouse_name text,p_ministry text,p_baptized text,p_birthday date
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $function$
DECLARE v_id uuid; v_email text; v_attempts integer;
BEGIN
  v_email := lower(btrim(COALESCE(p_email, '')));
  IF p_name IS NULL OR length(btrim(p_name)) < 3 OR length(btrim(p_name)) > 150
     OR p_phone IS NULL OR length(btrim(p_phone)) < 7 OR length(btrim(p_phone)) > 30
     OR v_email = '' OR length(v_email) > 254 OR position('@' IN v_email) < 2
     OR p_birthday IS NULL OR p_marital_status IS NULL OR length(p_marital_status) > 40
     OR p_spouse_type NOT IN ('none', 'text')
     OR COALESCE(length(p_spouse_name), 0) > 150 OR COALESCE(length(p_address), 0) > 300
     OR p_ministry IS NULL OR length(p_ministry) > 100
     OR p_baptized IS NULL OR length(p_baptized) > 20 THEN
    RAISE EXCEPTION 'Completa correctamente los campos obligatorios';
  END IF;
  INSERT INTO public.registro_publico_intentos(email, window_started_at, attempts)
  VALUES (v_email, now(), 1)
  ON CONFLICT (email) DO UPDATE
    SET attempts = CASE
          WHEN public.registro_publico_intentos.window_started_at < now() - interval '1 hour' THEN 1
          ELSE public.registro_publico_intentos.attempts + 1 END,
        window_started_at = CASE
          WHEN public.registro_publico_intentos.window_started_at < now() - interval '1 hour' THEN now()
          ELSE public.registro_publico_intentos.window_started_at END
  RETURNING attempts INTO v_attempts;
  IF v_attempts > 3 THEN
    RAISE EXCEPTION 'Has realizado demasiados intentos de registro para este correo. Inténtalo nuevamente más tarde.';
  END IF;
  INSERT INTO public.solicitudes_registro_miembros (
    name,phone,email,address,marital_status,spouse_type,spouse_name,spouse_id,
    ministry,baptized,birthday,status
  ) VALUES (
    btrim(p_name),btrim(p_phone),v_email,NULLIF(btrim(COALESCE(p_address,'')),''),
    p_marital_status,p_spouse_type,NULLIF(btrim(COALESCE(p_spouse_name,'')),''),
    NULL,p_ministry,p_baptized,p_birthday,'Activo'
  )
  ON CONFLICT (lower(email)) WHERE estado_solicitud = 'pendiente'
  DO UPDATE SET
    name=EXCLUDED.name,phone=EXCLUDED.phone,address=EXCLUDED.address,
    marital_status=EXCLUDED.marital_status,spouse_type=EXCLUDED.spouse_type,
    spouse_name=EXCLUDED.spouse_name,spouse_id=EXCLUDED.spouse_id,
    ministry=EXCLUDED.ministry,baptized=EXCLUDED.baptized,birthday=EXCLUDED.birthday
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$function$;
REVOKE ALL ON FUNCTION public.crear_solicitud_registro_miembro(text,text,text,text,text,text,text,text,text,date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.crear_solicitud_registro_miembro(text,text,text,text,text,text,text,text,text,date) TO anon, authenticated;
DROP POLICY IF EXISTS solicitudes_miembros_public_insert ON public.solicitudes_registro_miembros;

-- Fotos privadas; administradores/gestores y el titular pueden obtener enlaces temporales.
CREATE OR REPLACE FUNCTION public.app_puede_ver_foto_perfil(p_path text)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER
SET search_path TO 'pg_catalog', 'public'
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM public.perfiles_app AS p
    JOIN public.miembros_app AS m ON m.id = p.miembro_id
    WHERE p.id = (SELECT auth.uid()) AND p.activo = true
      AND (
        m.avatar = p_path
        OR m.avatar = 'storage:profile-photos/' || p_path
        OR m.avatar LIKE '%/storage/v1/object/public/profile-photos/' || p_path
        OR m.avatar LIKE '%/storage/v1/object/sign/profile-photos/' || p_path
      )
  );
$function$;
REVOKE ALL ON FUNCTION public.app_puede_ver_foto_perfil(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.app_puede_ver_foto_perfil(text) TO authenticated;
DROP POLICY IF EXISTS profile_photos_pending_upload ON storage.objects;
UPDATE storage.buckets SET public = false WHERE id = 'profile-photos';
DROP POLICY IF EXISTS profile_photos_manager_read ON storage.objects;
CREATE POLICY profile_photos_manager_read ON storage.objects FOR SELECT TO authenticated
USING (
  bucket_id = 'profile-photos' AND (
    public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor')
    OR public.app_tiene_rol_exacto('lider') OR public.app_tiene_rol_exacto('servidor')
    OR public.app_puede_ver_foto_perfil(name)
  )
);
DROP POLICY IF EXISTS profile_photos_admin_manage ON storage.objects;
CREATE POLICY profile_photos_admin_manage ON storage.objects FOR ALL TO authenticated
USING (bucket_id = 'profile-photos' AND public.app_tiene_rol_exacto('admin'))
WITH CHECK (bucket_id = 'profile-photos' AND public.app_tiene_rol_exacto('admin'));
DROP POLICY IF EXISTS sitio_publico_admin_manage ON storage.objects;
CREATE POLICY sitio_publico_admin_manage ON storage.objects FOR ALL TO authenticated
USING (bucket_id = 'sitio-publico' AND public.app_tiene_rol_exacto('admin'))
WITH CHECK (bucket_id = 'sitio-publico' AND public.app_tiene_rol_exacto('admin'));

ALTER TABLE public.solicitudes_registro_miembros
  DROP CONSTRAINT IF EXISTS solicitudes_registro_miembros_reviewed_by_fkey;
ALTER TABLE public.solicitudes_registro_miembros
  ADD CONSTRAINT solicitudes_registro_miembros_reviewed_by_fkey
  FOREIGN KEY (reviewed_by) REFERENCES auth.users(id) ON DELETE SET NULL;

-- Índices de soporte para claves foráneas.
CREATE INDEX IF NOT EXISTS idx_anuncios_creado_por ON public.anuncios(creado_por);
CREATE INDEX IF NOT EXISTS idx_avisos_congregacion_created_by ON public.avisos_congregacion(created_by);
CREATE INDEX IF NOT EXISTS idx_miembros_created_by ON public.miembros(created_by);
CREATE INDEX IF NOT EXISTS idx_miembros_app_created_by ON public.miembros_app(created_by);
CREATE INDEX IF NOT EXISTS idx_notas_lideres_lider_id ON public.notas_lideres(lider_id);
CREATE INDEX IF NOT EXISTS idx_notas_lideres_updated_by ON public.notas_lideres(updated_by);
CREATE INDEX IF NOT EXISTS idx_notas_pastorales_updated_by ON public.notas_pastorales(updated_by);
CREATE INDEX IF NOT EXISTS idx_peticiones_oracion_created_by ON public.peticiones_oracion(created_by);
CREATE INDEX IF NOT EXISTS idx_peticiones_oracion_member_id ON public.peticiones_oracion(member_id);
CREATE INDEX IF NOT EXISTS idx_solicitudes_registro_reviewed_by ON public.solicitudes_registro_miembros(reviewed_by);
CREATE INDEX IF NOT EXISTS idx_suscripciones_push_usuario_id ON public.suscripciones_push(usuario_id);

-- Políticas RLS con funciones Auth evaluadas una vez por sentencia.
ALTER POLICY perfiles_select_propio_o_admin ON public.perfiles_app
  USING ((id = (SELECT auth.uid())) OR (SELECT public.app_tiene_rol_exacto('admin')));
ALTER POLICY anuncios_insert_admin_pastor ON public.anuncios
  WITH CHECK ((SELECT public.app_puede_gestionar_anuncios()) AND creado_por = (SELECT auth.uid()));
ALTER POLICY avisos_insert_admin ON public.avisos_congregacion
  WITH CHECK ((SELECT public.app_tiene_rol_exacto('admin')) AND created_by = (SELECT auth.uid()));
ALTER POLICY suscripciones_push_select_own ON public.suscripciones_push
  USING (usuario_id = (SELECT auth.uid()));
ALTER POLICY suscripciones_push_insert_own ON public.suscripciones_push
  WITH CHECK (usuario_id = (SELECT auth.uid()));
ALTER POLICY suscripciones_push_update_own ON public.suscripciones_push
  USING (usuario_id = (SELECT auth.uid())) WITH CHECK (usuario_id = (SELECT auth.uid()));
ALTER POLICY suscripciones_push_delete_own ON public.suscripciones_push
  USING (usuario_id = (SELECT auth.uid()));
