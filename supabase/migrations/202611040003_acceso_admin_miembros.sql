-- Permite aprovisionamiento administrativo seguro desde una ficha activa.
-- El marcador vive en raw_app_meta_data (app_metadata), que el usuario no puede editar.
CREATE OR REPLACE FUNCTION public.crear_perfil_pendiente_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog'
AS $function$
DECLARE
  v_solicitud_id uuid;
  v_solicitud public.solicitudes_registro_miembros%ROWTYPE;
  v_miembro public.miembros_app%ROWTYPE;
  v_member_id text;
BEGIN
  IF NEW.raw_app_meta_data->>'renacer_admin_provisioned' = 'true' THEN
    v_member_id := NEW.raw_app_meta_data->>'renacer_member_id';
    SELECT * INTO v_miembro
      FROM public.miembros_app
      WHERE id = v_member_id
      FOR UPDATE;
    IF NOT FOUND OR v_miembro.status <> 'Activo'
       OR LOWER(BTRIM(COALESCE(v_miembro.email,''))) <> LOWER(BTRIM(NEW.email)) THEN
      RAISE EXCEPTION 'La ficha debe existir, estar activa y tener el mismo correo de la cuenta.';
    END IF;
    IF EXISTS (
      SELECT 1 FROM public.perfiles_app
      WHERE miembro_id = v_member_id OR LOWER(usuario) = LOWER(NEW.email)
    ) THEN
      RAISE EXCEPTION 'La ficha o el correo ya están vinculados a una cuenta.';
    END IF;
    INSERT INTO public.perfiles_app
      (id,nombre,usuario,rol,roles,activo,estado_solicitud,miembro_id)
    VALUES
      (NEW.id,v_miembro.name,LOWER(NEW.email),'miembro',ARRAY['miembro']::text[],TRUE,'aprobado',v_member_id);
    RETURN NEW;
  END IF;

  IF COALESCE(NEW.raw_user_meta_data->>'tipo_cuenta','') NOT IN ('miembro','hermano') THEN
    RAISE EXCEPTION 'El registro público solo permite cuentas de miembros.';
  END IF;
  BEGIN
    v_solicitud_id := (NEW.raw_user_meta_data->>'solicitud_id')::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'Solicitud de incorporación no válida';
  END;
  SELECT * INTO v_solicitud
    FROM public.solicitudes_registro_miembros
    WHERE id=v_solicitud_id FOR UPDATE;
  IF NOT FOUND OR v_solicitud.estado_solicitud<>'pendiente'
     OR LOWER(BTRIM(v_solicitud.email))<>LOWER(BTRIM(NEW.email)) THEN
    RAISE EXCEPTION 'No existe una solicitud pendiente válida para este correo';
  END IF;
  IF v_solicitud.auth_user_id IS NOT NULL THEN
    RAISE EXCEPTION 'La solicitud ya tiene una cuenta asociada';
  END IF;
  IF EXISTS(SELECT 1 FROM public.miembros_app WHERE LOWER(email)=LOWER(NEW.email)) THEN
    RAISE EXCEPTION 'Este correo ya está asociado a un miembro registrado';
  END IF;
  IF EXISTS(SELECT 1 FROM public.perfiles_app WHERE LOWER(usuario)=LOWER(NEW.email)) THEN
    RAISE EXCEPTION 'Este correo ya tiene un perfil en la aplicación';
  END IF;
  INSERT INTO public.perfiles_app(id,nombre,usuario,rol,roles,activo,estado_solicitud,miembro_id)
  VALUES(NEW.id,v_solicitud.name,LOWER(NEW.email),'miembro',ARRAY['miembro']::text[],FALSE,'pendiente',NULL)
  ON CONFLICT(id) DO NOTHING;
  UPDATE public.solicitudes_registro_miembros SET auth_user_id=NEW.id WHERE id=v_solicitud_id;
  RETURN NEW;
END;
$function$;
