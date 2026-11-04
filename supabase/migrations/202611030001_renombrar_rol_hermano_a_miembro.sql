-- Renombra el rol interno hermano a miembro y conserva sus restricciones de acceso.
CREATE OR REPLACE FUNCTION public.app_roles_valid(p_roles text[])
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO 'pg_catalog'
AS $f$ SELECT p_roles IS NOT NULL AND cardinality(p_roles) BETWEEN 1 AND 5
AND p_roles <@ ARRAY['admin','pastor','lider','servidor','miembro']::text[]
AND cardinality(p_roles)=(SELECT COUNT(DISTINCT x)::integer FROM unnest(p_roles) x); $f$;

CREATE OR REPLACE FUNCTION public.sincronizar_roles_perfil_renacer()
RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog' AS $f$
DECLARE v_roles text[];
BEGIN
 IF TG_OP='INSERT' AND (NEW.roles IS NULL OR NEW.roles=ARRAY['miembro']::text[] OR NEW.roles=ARRAY['hermano']::text[]) THEN
  v_roles:=ARRAY[COALESCE(NEW.rol,'miembro')]::text[];
 ELSIF TG_OP='UPDATE' AND NEW.roles IS NOT DISTINCT FROM OLD.roles AND NEW.rol IS DISTINCT FROM OLD.rol THEN
  v_roles:=ARRAY[COALESCE(NEW.rol,'miembro')]::text[];
 ELSE v_roles:=NEW.roles; END IF;
 SELECT array_agg(role_name ORDER BY priority) INTO v_roles FROM (
  SELECT role_name, MIN(priority) priority FROM (
   SELECT DISTINCT CASE old_role WHEN 'escritura' THEN 'pastor' WHEN 'lectura' THEN 'miembro' WHEN 'hermano' THEN 'miembro' ELSE old_role END role_name
   FROM unnest(COALESCE(v_roles,ARRAY[]::text[])) old_role
  ) n
  CROSS JOIN LATERAL (SELECT CASE role_name WHEN 'admin' THEN 1 WHEN 'pastor' THEN 2 WHEN 'lider' THEN 3 WHEN 'servidor' THEN 4 WHEN 'miembro' THEN 5 ELSE 6 END priority) p
  GROUP BY role_name
 ) ordered_roles;
 IF v_roles IS NULL OR cardinality(v_roles)<1 OR cardinality(v_roles)>5
 OR EXISTS(SELECT 1 FROM unnest(v_roles) x WHERE x NOT IN ('admin','pastor','lider','servidor','miembro')) THEN
  RAISE EXCEPTION 'Roles no válidos. Selecciona uno o más roles disponibles.';
 END IF;
 NEW.roles:=v_roles; NEW.rol:=v_roles[1]; RETURN NEW;
END; $f$;

CREATE OR REPLACE FUNCTION public.app_miembro_id_actual()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO 'pg_catalog'
AS $f$ SELECT miembro_id FROM public.perfiles_app WHERE id=auth.uid() AND activo=TRUE AND roles @> ARRAY['miembro']::text[] LIMIT 1; $f$;

CREATE OR REPLACE FUNCTION public.crear_perfil_pendiente_renacer()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog' AS $f$
DECLARE v_solicitud_id uuid; v_solicitud public.solicitudes_registro_miembros%ROWTYPE;
BEGIN
 IF COALESCE(NEW.raw_user_meta_data->>'tipo_cuenta','') NOT IN ('miembro','hermano') THEN RAISE EXCEPTION 'El registro público solo permite cuentas de miembros.'; END IF;
 BEGIN v_solicitud_id:=(NEW.raw_user_meta_data->>'solicitud_id')::uuid;
 EXCEPTION WHEN invalid_text_representation THEN RAISE EXCEPTION 'Solicitud de incorporación no válida'; END;
 SELECT * INTO v_solicitud FROM public.solicitudes_registro_miembros WHERE id=v_solicitud_id FOR UPDATE;
 IF NOT FOUND OR v_solicitud.estado_solicitud<>'pendiente' OR LOWER(BTRIM(v_solicitud.email))<>LOWER(BTRIM(NEW.email)) THEN RAISE EXCEPTION 'No existe una solicitud pendiente válida para este correo'; END IF;
 IF v_solicitud.auth_user_id IS NOT NULL THEN RAISE EXCEPTION 'La solicitud ya tiene una cuenta asociada'; END IF;
 IF EXISTS(SELECT 1 FROM public.miembros_app WHERE LOWER(email)=LOWER(NEW.email)) THEN RAISE EXCEPTION 'Este correo ya está asociado a un miembro registrado'; END IF;
 IF EXISTS(SELECT 1 FROM public.perfiles_app WHERE LOWER(usuario)=LOWER(NEW.email)) THEN RAISE EXCEPTION 'Este correo ya tiene un perfil en la aplicación'; END IF;
 INSERT INTO public.perfiles_app(id,nombre,usuario,rol,roles,activo,estado_solicitud,miembro_id)
 VALUES(NEW.id,v_solicitud.name,LOWER(NEW.email),'miembro',ARRAY['miembro']::text[],FALSE,'pendiente',NULL) ON CONFLICT(id) DO NOTHING;
 UPDATE public.solicitudes_registro_miembros SET auth_user_id=NEW.id WHERE id=v_solicitud_id;
 RETURN NEW;
END; $f$;

CREATE OR REPLACE FUNCTION public.aprobar_solicitud_registro_miembro(p_solicitud_id uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'pg_catalog' AS $f$
DECLARE v_solicitud public.solicitudes_registro_miembros%ROWTYPE; v_nuevo_miembro_id text; v_perfil_id uuid;
BEGIN
 IF auth.uid() IS NULL OR NOT public.app_tiene_rol('admin') THEN RAISE EXCEPTION 'Solo un administrador puede aprobar solicitudes'; END IF;
 SELECT * INTO v_solicitud FROM public.solicitudes_registro_miembros WHERE id=p_solicitud_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Solicitud no encontrada'; END IF;
 IF v_solicitud.estado_solicitud<>'pendiente' THEN RAISE EXCEPTION 'La solicitud ya fue revisada'; END IF;
 IF v_solicitud.email IS NULL OR v_solicitud.auth_user_id IS NULL THEN RAISE EXCEPTION 'La solicitud no tiene una cuenta Auth vinculada'; END IF;
 SELECT id INTO v_perfil_id FROM public.perfiles_app WHERE id=v_solicitud.auth_user_id
 AND (roles @> ARRAY['miembro']::text[] OR roles @> ARRAY['hermano']::text[]) AND activo=FALSE
 AND estado_solicitud='pendiente' AND miembro_id IS NULL FOR UPDATE;
 IF v_perfil_id IS NULL THEN RAISE EXCEPTION 'No existe un perfil de miembro pendiente válido'; END IF;
 IF EXISTS(SELECT 1 FROM public.miembros_app WHERE LOWER(email)=LOWER(v_solicitud.email)) THEN RAISE EXCEPTION 'Ya existe un miembro con este correo electrónico'; END IF;
 v_nuevo_miembro_id:=gen_random_uuid()::text;
 INSERT INTO public.miembros_app(id,name,phone,email,address,marital_status,spouse_type,spouse_name,spouse_id,ministry,status,baptized,birthday)
 VALUES(v_nuevo_miembro_id,v_solicitud.name,v_solicitud.phone,LOWER(v_solicitud.email),v_solicitud.address,v_solicitud.marital_status,
 v_solicitud.spouse_type,v_solicitud.spouse_name,v_solicitud.spouse_id,v_solicitud.ministry,v_solicitud.status,v_solicitud.baptized,v_solicitud.birthday);
 UPDATE public.perfiles_app SET miembro_id=v_nuevo_miembro_id,activo=TRUE,estado_solicitud='aprobado',nombre=v_solicitud.name,rol='miembro',roles=ARRAY['miembro']::text[] WHERE id=v_perfil_id;
 UPDATE public.solicitudes_registro_miembros SET estado_solicitud='aprobado',reviewed_at=now(),reviewed_by=auth.uid() WHERE id=p_solicitud_id;
 RETURN v_nuevo_miembro_id;
END; $f$;

DROP POLICY IF EXISTS miembros_app_select_privacidad ON public.miembros_app;
CREATE POLICY miembros_app_select_privacidad ON public.miembros_app FOR SELECT TO authenticated
USING(public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider')
OR public.app_tiene_rol_exacto('servidor') OR (public.app_tiene_rol_exacto('miembro') AND id=public.app_miembro_id_actual()));

UPDATE public.perfiles_app SET roles=array_replace(roles,'hermano','miembro'), rol=CASE rol WHEN 'hermano' THEN 'miembro' ELSE rol END
WHERE rol='hermano' OR roles @> ARRAY['hermano']::text[];
