-- Eliminar el rol Servidor y asignar sus permisos adicionales al ministerio Servidor.
BEGIN;

-- Preservar, si existieran, los antiguos perfiles con rol servidor.
UPDATE public.miembros_app m
SET ministry='Servidor', updated_at=now()
FROM public.perfiles_app p
WHERE p.miembro_id=m.id AND p.roles @> ARRAY['servidor']::text[]
  AND COALESCE(m.ministry,'General')='General';
UPDATE public.perfiles_app
SET roles=ARRAY['miembro']::text[]
WHERE roles @> ARRAY['servidor']::text[];

CREATE OR REPLACE FUNCTION public.app_roles_valid(p_roles text[])
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO 'pg_catalog'
AS $$
 SELECT p_roles IS NOT NULL
   AND cardinality(p_roles)=1
   AND p_roles <@ ARRAY['admin','pastor','lider','miembro']::text[];
$$;

CREATE OR REPLACE FUNCTION public.sincronizar_roles_perfil_renacer()
RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog'
AS $function$
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
  CROSS JOIN LATERAL (SELECT CASE role_name WHEN 'admin' THEN 1 WHEN 'pastor' THEN 2 WHEN 'lider' THEN 3 WHEN 'miembro' THEN 4 ELSE 5 END priority) p
  GROUP BY role_name
 ) ordered_roles;
 IF v_roles IS NULL OR cardinality(v_roles)<1 OR cardinality(v_roles)>4
 OR EXISTS(SELECT 1 FROM unnest(v_roles) x WHERE x NOT IN ('admin','pastor','lider','miembro')) THEN
  RAISE EXCEPTION 'Rol no válido. Selecciona Administrador, Pastor, Líder o Miembro.';
 END IF;
 NEW.roles:=v_roles; NEW.rol:=v_roles[1]; RETURN NEW;
END; $function$;

CREATE OR REPLACE FUNCTION private.app_es_servidor_actual()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO 'pg_catalog'
AS $function$
 SELECT EXISTS (
  SELECT 1
  FROM public.perfiles_app p
  JOIN public.miembros_app m ON m.id=p.miembro_id
  WHERE p.id=(SELECT auth.uid()) AND p.activo=true AND m.ministry='Servidor'
 );
$function$;
REVOKE ALL ON FUNCTION private.app_es_servidor_actual() FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION private.app_es_servidor_actual() TO authenticated;

DROP POLICY IF EXISTS miembros_app_select_privacidad ON public.miembros_app;
CREATE POLICY miembros_app_select_privacidad ON public.miembros_app
FOR SELECT TO authenticated
USING (
 public.app_tiene_rol_exacto('admin')
 OR public.app_tiene_rol_exacto('pastor')
 OR (public.app_tiene_rol_exacto('lider')
     AND private.app_ministerio_lider_actual() IS NOT NULL
     AND ministry=private.app_ministerio_lider_actual())
 OR (private.app_es_servidor_actual() AND status='En Visita')
 OR (private.app_es_servidor_actual() AND id=public.app_miembro_id_actual())
 OR (public.app_tiene_rol_exacto('miembro') AND id=public.app_miembro_id_actual())
);

DROP POLICY IF EXISTS miembros_app_insert_gestores ON public.miembros_app;
CREATE POLICY miembros_app_insert_gestores ON public.miembros_app
FOR INSERT TO authenticated
WITH CHECK (
 public.app_tiene_rol_exacto('admin')
 OR public.app_tiene_rol_exacto('pastor')
 OR (private.app_es_servidor_actual() AND status='En Visita')
);

DROP POLICY IF EXISTS peticiones_delete_gestores ON public.peticiones_oracion;
CREATE POLICY peticiones_delete_gestores ON public.peticiones_oracion
FOR DELETE TO authenticated
USING (
 public.app_tiene_rol_exacto('admin')
 OR public.app_tiene_rol_exacto('pastor')
 OR private.app_es_servidor_actual()
);

DROP POLICY IF EXISTS profile_photos_manager_read ON storage.objects;
CREATE POLICY profile_photos_manager_read ON storage.objects
FOR SELECT TO authenticated
USING (
 bucket_id='profile-photos'
 AND (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
  OR public.app_tiene_rol_exacto('lider')
  OR private.app_es_servidor_actual()
  OR public.app_puede_ver_foto_perfil(name)
 )
);

COMMIT;
