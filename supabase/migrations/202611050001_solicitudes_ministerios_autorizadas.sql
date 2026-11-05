-- Solicitudes de ingreso a ministerios con autorización de líder o administrador.
BEGIN;

CREATE TABLE IF NOT EXISTS public.solicitudes_ministerio (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 miembro_id text NOT NULL REFERENCES public.miembros_app(id) ON DELETE CASCADE,
 solicitado_por uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 ministerio text NOT NULL CHECK (ministerio = ANY (ARRAY['Alabanza','Servidor','Niños','Jóvenes','Oración','Evangelismo','Redes','Damas','Matrimonio','Hombres']::text[])),
 estado text NOT NULL DEFAULT 'pendiente' CHECK (estado = ANY (ARRAY['pendiente','aprobado','rechazado','cancelado']::text[])),
 creado_en timestamptz NOT NULL DEFAULT now(),
 revisado_en timestamptz,
 revisado_por uuid REFERENCES auth.users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS solicitudes_ministerio_una_pendiente_por_miembro ON public.solicitudes_ministerio(miembro_id) WHERE estado='pendiente';
CREATE INDEX IF NOT EXISTS solicitudes_ministerio_estado_ministerio_idx ON public.solicitudes_ministerio(estado,ministerio,creado_en);
ALTER TABLE public.solicitudes_ministerio ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.solicitudes_ministerio FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.solicitar_ingreso_ministerio(p_ministerio text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $$
DECLARE v_miembro_id text; v_estado text; v_actual text; v_id uuid;
BEGIN
 IF auth.uid() IS NULL OR NOT public.app_perfil_activo() OR NOT public.app_tiene_rol_exacto('miembro') THEN
  RAISE EXCEPTION 'Solo un miembro con cuenta activa puede solicitar ingreso a un ministerio.';
 END IF;
 IF p_ministerio IS NULL OR p_ministerio NOT IN ('Alabanza','Servidor','Niños','Jóvenes','Oración','Evangelismo','Redes','Damas','Matrimonio','Hombres') THEN
  RAISE EXCEPTION 'Selecciona un ministerio válido.';
 END IF;
 SELECT p.miembro_id,m.status,COALESCE(m.ministry,'General') INTO v_miembro_id,v_estado,v_actual
 FROM public.perfiles_app p JOIN public.miembros_app m ON m.id=p.miembro_id
 WHERE p.id=auth.uid() AND p.activo=true FOR UPDATE OF m;
 IF v_miembro_id IS NULL OR v_estado <> 'Activo' THEN RAISE EXCEPTION 'Tu cuenta debe estar vinculada a una ficha activa.'; END IF;
 IF v_actual <> 'General' THEN RAISE EXCEPTION 'Ya perteneces a un ministerio.'; END IF;
 INSERT INTO public.solicitudes_ministerio(miembro_id,solicitado_por,ministerio)
 VALUES(v_miembro_id,auth.uid(),p_ministerio) RETURNING id INTO v_id;
 RETURN v_id;
END; $$;

CREATE OR REPLACE FUNCTION public.mi_estado_solicitud_ministerio()
RETURNS TABLE(ministerio_solicitado text,estado text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT s.ministerio,s.estado FROM public.solicitudes_ministerio s
 JOIN public.perfiles_app p ON p.miembro_id=s.miembro_id
 WHERE p.id=auth.uid() AND p.activo=true AND s.estado IN ('pendiente','rechazado')
 ORDER BY s.creado_en DESC LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.listar_solicitudes_ministerio_pendientes()
RETURNS TABLE(solicitud_id uuid,miembro_id text,nombre text,ministerio text,creado_en timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $$
DECLARE v_ministerio_lider text; v_admin boolean;
BEGIN
 IF auth.uid() IS NULL OR NOT public.app_perfil_activo() THEN RAISE EXCEPTION 'Debes iniciar sesión con una cuenta activa.'; END IF;
 v_admin:=public.app_tiene_rol_exacto('admin');
 IF NOT v_admin AND NOT public.app_tiene_rol_exacto('lider') THEN RAISE EXCEPTION 'No tienes permiso para revisar solicitudes.'; END IF;
 IF NOT v_admin THEN
  v_ministerio_lider:=private.app_ministerio_lider_actual();
  IF v_ministerio_lider IS NULL THEN RAISE EXCEPTION 'Tu perfil de líder no tiene un ministerio asignado.'; END IF;
 END IF;
 RETURN QUERY SELECT s.id,s.miembro_id,m.name,s.ministerio,s.creado_en
 FROM public.solicitudes_ministerio s JOIN public.miembros_app m ON m.id=s.miembro_id
 WHERE s.estado='pendiente' AND (v_admin OR s.ministerio=v_ministerio_lider) ORDER BY s.creado_en ASC;
END; $$;

CREATE OR REPLACE FUNCTION public.resolver_solicitud_ministerio(p_solicitud_id uuid,p_aprobar boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $$
DECLARE v_s public.solicitudes_ministerio%ROWTYPE; v_lider_min text; v_admin boolean;
BEGIN
 IF auth.uid() IS NULL OR NOT public.app_perfil_activo() THEN RAISE EXCEPTION 'Debes iniciar sesión con una cuenta activa.'; END IF;
 v_admin:=public.app_tiene_rol_exacto('admin');
 IF NOT v_admin AND NOT public.app_tiene_rol_exacto('lider') THEN RAISE EXCEPTION 'No tienes permiso para resolver solicitudes.'; END IF;
 SELECT * INTO v_s FROM public.solicitudes_ministerio WHERE id=p_solicitud_id AND estado='pendiente' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'La solicitud ya fue revisada o no existe.'; END IF;
 IF NOT v_admin THEN
  v_lider_min:=private.app_ministerio_lider_actual();
  IF v_lider_min IS NULL OR v_lider_min<>v_s.ministerio THEN RAISE EXCEPTION 'Solo puedes revisar solicitudes de tu propio ministerio.'; END IF;
 END IF;
 IF p_aprobar THEN
  UPDATE public.miembros_app SET ministry=v_s.ministerio,updated_at=now()
  WHERE id=v_s.miembro_id AND status='Activo' AND COALESCE(ministry,'General')='General';
  IF NOT FOUND THEN RAISE EXCEPTION 'El miembro ya pertenece a otro ministerio o su ficha no está activa.'; END IF;
 END IF;
 UPDATE public.solicitudes_ministerio SET estado=CASE WHEN p_aprobar THEN 'aprobado' ELSE 'rechazado' END,
 revisado_en=now(),revisado_por=auth.uid() WHERE id=p_solicitud_id;
END; $$;

CREATE OR REPLACE FUNCTION public.quitar_miembro_de_ministerio(p_miembro_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $$
DECLARE v_actual text; v_admin boolean;
BEGIN
 IF auth.uid() IS NULL OR NOT public.app_perfil_activo() THEN RAISE EXCEPTION 'Debes iniciar sesión con una cuenta activa.'; END IF;
 v_admin:=public.app_tiene_rol_exacto('admin');
 IF NOT v_admin AND NOT public.app_tiene_rol_exacto('lider') THEN RAISE EXCEPTION 'No tienes permiso para retirar miembros.'; END IF;
 SELECT COALESCE(ministry,'General') INTO v_actual FROM public.miembros_app WHERE id=p_miembro_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Miembro no encontrado.'; END IF;
 IF NOT v_admin AND (v_actual='General' OR v_actual<>private.app_ministerio_lider_actual()) THEN
  RAISE EXCEPTION 'Solo puedes retirar miembros de tu propio ministerio.';
 END IF;
 UPDATE public.miembros_app SET ministry='General',updated_at=now() WHERE id=p_miembro_id;
END; $$;

CREATE OR REPLACE FUNCTION public.admin_asignar_ministerio(p_miembro_id text,p_ministerio text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF auth.uid() IS NULL OR NOT public.app_perfil_activo() OR NOT public.app_tiene_rol_exacto('admin') THEN
  RAISE EXCEPTION 'Solo un administrador puede asignar ministerios directamente.';
 END IF;
 IF p_ministerio IS NULL OR p_ministerio NOT IN ('General','Alabanza','Servidor','Niños','Jóvenes','Oración','Evangelismo','Redes','Damas','Matrimonio','Hombres') THEN
  RAISE EXCEPTION 'Ministerio no válido.';
 END IF;
 UPDATE public.miembros_app SET ministry=p_ministerio,updated_at=now() WHERE id=p_miembro_id AND status='Activo';
 IF NOT FOUND THEN RAISE EXCEPTION 'Miembro activo no encontrado.'; END IF;
 UPDATE public.solicitudes_ministerio SET estado='cancelado',revisado_en=now(),revisado_por=auth.uid()
 WHERE miembro_id=p_miembro_id AND estado='pendiente';
END; $$;

-- El formulario público no acepta asignaciones ministeriales: todos ingresan a General.
CREATE OR REPLACE FUNCTION public.crear_solicitud_registro_miembro(
 p_name text,p_phone text,p_email text,p_address text,p_marital_status text,
 p_spouse_type text,p_spouse_name text,p_ministry text,p_baptized text,p_birthday date
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog','public'
AS $function$
DECLARE v_id uuid; v_email text; v_attempts integer;
BEGIN
 v_email:=lower(btrim(COALESCE(p_email,'')));
 IF p_name IS NULL OR length(btrim(p_name))<3 OR length(btrim(p_name))>150
 OR p_phone IS NULL OR length(btrim(p_phone))<7 OR length(btrim(p_phone))>30
 OR v_email='' OR length(v_email)>254 OR position('@' IN v_email)<2
 OR p_birthday IS NULL OR p_marital_status IS NULL OR length(p_marital_status)>40
 OR p_spouse_type NOT IN ('none','text')
 OR COALESCE(length(p_spouse_name),0)>150 OR COALESCE(length(p_address),0)>300
 OR p_ministry IS NULL OR length(p_ministry)>100
 OR p_baptized IS NULL OR length(p_baptized)>20 THEN
  RAISE EXCEPTION 'Completa correctamente los campos obligatorios';
 END IF;
 INSERT INTO public.registro_publico_intentos(email,window_started_at,attempts)
 VALUES(v_email,now(),1)
 ON CONFLICT(email) DO UPDATE SET
 attempts=CASE WHEN public.registro_publico_intentos.window_started_at<now()-interval '1 hour' THEN 1 ELSE public.registro_publico_intentos.attempts+1 END,
 window_started_at=CASE WHEN public.registro_publico_intentos.window_started_at<now()-interval '1 hour' THEN now() ELSE public.registro_publico_intentos.window_started_at END
 RETURNING attempts INTO v_attempts;
 IF v_attempts>3 THEN RAISE EXCEPTION 'Has realizado demasiados intentos de registro para este correo. Inténtalo nuevamente más tarde.'; END IF;
 INSERT INTO public.solicitudes_registro_miembros(name,phone,email,address,marital_status,spouse_type,spouse_name,spouse_id,ministry,baptized,birthday,status)
 VALUES(btrim(p_name),btrim(p_phone),v_email,NULLIF(btrim(COALESCE(p_address,'')),''),p_marital_status,p_spouse_type,
 NULLIF(btrim(COALESCE(p_spouse_name,'')),''),NULL,'General',p_baptized,p_birthday,'Activo')
 ON CONFLICT (lower(email)) WHERE estado_solicitud='pendiente'
 DO UPDATE SET name=EXCLUDED.name,phone=EXCLUDED.phone,address=EXCLUDED.address,
 marital_status=EXCLUDED.marital_status,spouse_type=EXCLUDED.spouse_type,
 spouse_name=EXCLUDED.spouse_name,spouse_id=EXCLUDED.spouse_id,
 ministry='General',baptized=EXCLUDED.baptized,birthday=EXCLUDED.birthday
 RETURNING id INTO v_id;
 RETURN v_id;
END;
$function$;

REVOKE ALL ON FUNCTION public.solicitar_ingreso_ministerio(text) FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.mi_estado_solicitud_ministerio() FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.listar_solicitudes_ministerio_pendientes() FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.resolver_solicitud_ministerio(uuid,boolean) FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.quitar_miembro_de_ministerio(text) FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.admin_asignar_ministerio(text,text) FROM PUBLIC,anon;
REVOKE ALL ON FUNCTION public.crear_solicitud_registro_miembro(text,text,text,text,text,text,text,text,text,date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.solicitar_ingreso_ministerio(text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.mi_estado_solicitud_ministerio() TO authenticated;
GRANT EXECUTE ON FUNCTION public.listar_solicitudes_ministerio_pendientes() TO authenticated;
GRANT EXECUTE ON FUNCTION public.resolver_solicitud_ministerio(uuid,boolean) TO authenticated;
GRANT EXECUTE ON FUNCTION public.quitar_miembro_de_ministerio(text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.admin_asignar_ministerio(text,text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.crear_solicitud_registro_miembro(text,text,text,text,text,text,text,text,text,date) TO anon,authenticated;

COMMENT ON TABLE public.solicitudes_ministerio IS 'Solicitudes de ingreso a ministerios aprobadas por su líder o un administrador.';
COMMIT;
