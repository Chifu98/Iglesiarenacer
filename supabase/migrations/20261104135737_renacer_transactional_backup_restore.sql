-- Restauración lógica transaccional de los datos de aplicación de Renacer.
-- No exporta/recrea usuarios Auth, contraseñas ni suscripciones push.
CREATE OR REPLACE FUNCTION public.restaurar_respaldo_renacer(p_data jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $function$
DECLARE v_total bigint := 0; v_rows bigint := 0;
BEGIN
  IF auth.uid() IS NULL OR NOT public.app_tiene_rol_exacto('admin') THEN
    RAISE EXCEPTION 'Solo un administrador puede restaurar respaldos.';
  END IF;
  IF p_data IS NULL OR jsonb_typeof(p_data) <> 'object' THEN
    RAISE EXCEPTION 'El contenido del respaldo no es válido.';
  END IF;
  IF EXISTS (
    SELECT 1 FROM jsonb_each(p_data) AS item
    WHERE item.key = ANY (ARRAY[
      'anuncios','avisos_congregacion','miembros','miembros_app',
      'notas_lideres','notas_pastorales','perfiles_app',
      'peticiones_oracion','registro_auditoria','solicitudes_registro_miembros'
    ]) AND jsonb_typeof(item.value) <> 'array'
  ) THEN
    RAISE EXCEPTION 'Una o más colecciones del respaldo no tienen formato de lista.';
  END IF;

  INSERT INTO public.miembros_app (
    id,name,phone,email,address,marital_status,spouse_type,spouse_name,spouse_id,
    ministry,status,baptized,birthday,avatar,created_at,updated_at,created_by,
    inviter_member_id,inviter_name,inviter_relationship
  )
  SELECT id,name,phone,email,address,marital_status,spouse_type,spouse_name,spouse_id,
         ministry,status,baptized,birthday,avatar,created_at,updated_at,created_by,
         inviter_member_id,inviter_name,inviter_relationship
  FROM jsonb_populate_recordset(NULL::public.miembros_app, COALESCE(p_data->'miembros_app','[]'::jsonb))
  ON CONFLICT (id) DO UPDATE SET
    name=EXCLUDED.name,phone=EXCLUDED.phone,email=EXCLUDED.email,address=EXCLUDED.address,
    marital_status=EXCLUDED.marital_status,spouse_type=EXCLUDED.spouse_type,
    spouse_name=EXCLUDED.spouse_name,spouse_id=EXCLUDED.spouse_id,ministry=EXCLUDED.ministry,
    status=EXCLUDED.status,baptized=EXCLUDED.baptized,birthday=EXCLUDED.birthday,
    avatar=EXCLUDED.avatar,created_at=EXCLUDED.created_at,updated_at=EXCLUDED.updated_at,
    created_by=EXCLUDED.created_by,inviter_member_id=EXCLUDED.inviter_member_id,
    inviter_name=EXCLUDED.inviter_name,inviter_relationship=EXCLUDED.inviter_relationship;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.miembros (
    id,nombre_completo,telefono,correo_electronico,direccion,estado_civil,ministerio,
    bautizado,fecha_nacimiento,fecha_registro,estado,observaciones,created_at,created_by
  )
  SELECT id,nombre_completo,telefono,correo_electronico,direccion,estado_civil,ministerio,
         bautizado,fecha_nacimiento,fecha_registro,estado,observaciones,created_at,created_by
  FROM jsonb_populate_recordset(NULL::public.miembros, COALESCE(p_data->'miembros','[]'::jsonb))
  ON CONFLICT (id) DO UPDATE SET
    nombre_completo=EXCLUDED.nombre_completo,telefono=EXCLUDED.telefono,
    correo_electronico=EXCLUDED.correo_electronico,direccion=EXCLUDED.direccion,
    estado_civil=EXCLUDED.estado_civil,ministerio=EXCLUDED.ministerio,
    bautizado=EXCLUDED.bautizado,fecha_nacimiento=EXCLUDED.fecha_nacimiento,
    fecha_registro=EXCLUDED.fecha_registro,estado=EXCLUDED.estado,
    observaciones=EXCLUDED.observaciones,created_at=EXCLUDED.created_at,created_by=EXCLUDED.created_by;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.perfiles_app (id,nombre,usuario,rol,activo,creado_en,estado_solicitud,miembro_id,roles)
  SELECT r.id,r.nombre,r.usuario,r.rol,r.activo,r.creado_en,r.estado_solicitud,r.miembro_id,r.roles
  FROM jsonb_populate_recordset(NULL::public.perfiles_app, COALESCE(p_data->'perfiles_app','[]'::jsonb)) AS r
  WHERE EXISTS (SELECT 1 FROM auth.users AS u WHERE u.id = r.id)
  ON CONFLICT (id) DO UPDATE SET
    nombre=EXCLUDED.nombre,usuario=EXCLUDED.usuario,rol=EXCLUDED.rol,
    activo=EXCLUDED.activo,creado_en=EXCLUDED.creado_en,
    estado_solicitud=EXCLUDED.estado_solicitud,miembro_id=EXCLUDED.miembro_id,roles=EXCLUDED.roles;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.notas_lideres (miembro_id,nota,updated_at,updated_by,lider_id)
  SELECT miembro_id,nota,updated_at,updated_by,lider_id
  FROM jsonb_populate_recordset(NULL::public.notas_lideres, COALESCE(p_data->'notas_lideres','[]'::jsonb))
  ON CONFLICT (miembro_id,lider_id) DO UPDATE SET
    nota=EXCLUDED.nota,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.notas_pastorales (miembro_id,nota,updated_at,updated_by)
  SELECT miembro_id,nota,updated_at,updated_by
  FROM jsonb_populate_recordset(NULL::public.notas_pastorales, COALESCE(p_data->'notas_pastorales','[]'::jsonb))
  ON CONFLICT (miembro_id) DO UPDATE SET
    nota=EXCLUDED.nota,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.peticiones_oracion (id,member_id,description,created_at,created_by,member_name)
  SELECT id,member_id,description,created_at,created_by,member_name
  FROM jsonb_populate_recordset(NULL::public.peticiones_oracion, COALESCE(p_data->'peticiones_oracion','[]'::jsonb))
  ON CONFLICT (id) DO UPDATE SET
    member_id=EXCLUDED.member_id,description=EXCLUDED.description,
    created_at=EXCLUDED.created_at,created_by=EXCLUDED.created_by,member_name=EXCLUDED.member_name;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.anuncios (id,titulo,contenido,creado_por,creado_en,actualizado_en)
  SELECT id,titulo,contenido,creado_por,creado_en,actualizado_en
  FROM jsonb_populate_recordset(NULL::public.anuncios, COALESCE(p_data->'anuncios','[]'::jsonb))
  ON CONFLICT (id) DO UPDATE SET
    titulo=EXCLUDED.titulo,contenido=EXCLUDED.contenido,creado_por=EXCLUDED.creado_por,
    creado_en=EXCLUDED.creado_en,actualizado_en=EXCLUDED.actualizado_en;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.avisos_congregacion (id,title,body,published,created_by,created_at,updated_at,published_at)
  SELECT id,title,body,published,created_by,created_at,updated_at,published_at
  FROM jsonb_populate_recordset(NULL::public.avisos_congregacion, COALESCE(p_data->'avisos_congregacion','[]'::jsonb))
  ON CONFLICT (id) DO UPDATE SET
    title=EXCLUDED.title,body=EXCLUDED.body,published=EXCLUDED.published,
    created_by=EXCLUDED.created_by,created_at=EXCLUDED.created_at,
    updated_at=EXCLUDED.updated_at,published_at=EXCLUDED.published_at;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.solicitudes_registro_miembros (
    id,name,phone,email,address,marital_status,spouse_type,spouse_name,spouse_id,
    ministry,status,baptized,birthday,estado_solicitud,created_at,reviewed_at,reviewed_by,auth_user_id
  )
  SELECT id,name,phone,email,address,marital_status,spouse_type,spouse_name,spouse_id,
         ministry,status,baptized,birthday,estado_solicitud,created_at,reviewed_at,reviewed_by,auth_user_id
  FROM jsonb_populate_recordset(NULL::public.solicitudes_registro_miembros, COALESCE(p_data->'solicitudes_registro_miembros','[]'::jsonb))
  ON CONFLICT (id) DO UPDATE SET
    name=EXCLUDED.name,phone=EXCLUDED.phone,email=EXCLUDED.email,address=EXCLUDED.address,
    marital_status=EXCLUDED.marital_status,spouse_type=EXCLUDED.spouse_type,
    spouse_name=EXCLUDED.spouse_name,spouse_id=EXCLUDED.spouse_id,ministry=EXCLUDED.ministry,
    status=EXCLUDED.status,baptized=EXCLUDED.baptized,birthday=EXCLUDED.birthday,
    estado_solicitud=EXCLUDED.estado_solicitud,created_at=EXCLUDED.created_at,
    reviewed_at=EXCLUDED.reviewed_at,reviewed_by=EXCLUDED.reviewed_by,auth_user_id=EXCLUDED.auth_user_id;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  INSERT INTO public.registro_auditoria
    (id,created_at,actor_id,actor_name,actor_role,action,entity_table,entity_id,changed_fields)
    OVERRIDING SYSTEM VALUE
  SELECT id,created_at,actor_id,actor_name,actor_role,action,entity_table,entity_id,changed_fields
  FROM jsonb_populate_recordset(NULL::public.registro_auditoria, COALESCE(p_data->'registro_auditoria','[]'::jsonb))
  ON CONFLICT (id) DO UPDATE SET
    created_at=EXCLUDED.created_at,actor_id=EXCLUDED.actor_id,actor_name=EXCLUDED.actor_name,
    actor_role=EXCLUDED.actor_role,action=EXCLUDED.action,entity_table=EXCLUDED.entity_table,
    entity_id=EXCLUDED.entity_id,changed_fields=EXCLUDED.changed_fields;
  GET DIAGNOSTICS v_rows = ROW_COUNT; v_total := v_total + v_rows;

  PERFORM setval(
    pg_get_serial_sequence('public.registro_auditoria','id'),
    COALESCE((SELECT max(id) FROM public.registro_auditoria), 1),
    EXISTS (SELECT 1 FROM public.registro_auditoria)
  );
  RETURN jsonb_build_object('success', true, 'rows_restored', v_total);
END;
$function$;
REVOKE ALL ON FUNCTION public.restaurar_respaldo_renacer(jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.restaurar_respaldo_renacer(jsonb) TO authenticated;
