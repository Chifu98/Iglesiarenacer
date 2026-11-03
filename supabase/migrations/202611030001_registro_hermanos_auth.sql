-- Iglesia Renacer: registro de hermanos con cuenta Auth previa a aprobación.
-- Ejecutar en Supabase SQL Editor después de respaldar la base de datos.
BEGIN;

ALTER TABLE public.solicitudes_registro_miembros
  ADD COLUMN IF NOT EXISTS auth_user_id uuid
  REFERENCES auth.users(id) ON DELETE SET NULL;

-- El formulario público exige correo; evita solicitudes nuevas sin identidad de acceso.
ALTER TABLE public.solicitudes_registro_miembros
  ALTER COLUMN email SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS solicitudes_registro_miembros_auth_user_id_uidx
  ON public.solicitudes_registro_miembros(auth_user_id)
  WHERE auth_user_id IS NOT NULL;

-- El trigger conserva el flujo existente de servidores/lectura.
-- Para hermanos, valida solicitud y correo, crea perfil bloqueado y vincula la solicitud.
CREATE OR REPLACE FUNCTION public.crear_perfil_pendiente_renacer()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_nombre text;
  v_tipo text;
  v_solicitud_id uuid;
  v_solicitud public.solicitudes_registro_miembros%ROWTYPE;
  v_miembro_id text;
BEGIN
  v_nombre := COALESCE(
    NULLIF(BTRIM(NEW.raw_user_meta_data ->> 'nombre'), ''),
    split_part(COALESCE(NEW.email, ''), '@', 1)
  );
  v_tipo := COALESCE(NEW.raw_user_meta_data ->> 'tipo_cuenta', '');

  IF v_tipo = 'hermano' THEN
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

    IF EXISTS (
      SELECT 1 FROM public.miembros_app
      WHERE LOWER(email) = LOWER(NEW.email)
    ) THEN
      RAISE EXCEPTION 'Este correo ya está asociado a un miembro registrado';
    END IF;

    IF EXISTS (
      SELECT 1 FROM public.perfiles_app
      WHERE LOWER(usuario) = LOWER(NEW.email)
    ) THEN
      RAISE EXCEPTION 'Este correo ya tiene un perfil en la aplicación';
    END IF;

    INSERT INTO public.perfiles_app
      (id, nombre, usuario, rol, activo, estado_solicitud, miembro_id)
    VALUES
      (NEW.id, v_solicitud.name, LOWER(NEW.email), 'hermano', false, 'pendiente', NULL)
    ON CONFLICT (id) DO NOTHING;

    UPDATE public.solicitudes_registro_miembros
    SET auth_user_id = NEW.id
    WHERE id = v_solicitud_id;

    RETURN NEW;
  END IF;

  -- Flujo preexistente para servidores y demás solicitudes internas.
  INSERT INTO public.perfiles_app
    (id, nombre, usuario, rol, activo, estado_solicitud, miembro_id)
  VALUES
    (NEW.id, v_nombre, LOWER(NEW.email), 'lectura', false, 'pendiente', NULL)
  ON CONFLICT (id) DO NOTHING;

  RETURN NEW;
END;
$$;

-- La aprobación crea el miembro y habilita/vincula el perfil en la misma transacción.
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
  IF auth.uid() IS NULL OR public.app_rol_actual() IS DISTINCT FROM 'admin' THEN
    RAISE EXCEPTION 'Solo un administrador puede aprobar solicitudes';
  END IF;

  SELECT * INTO v_solicitud
  FROM public.solicitudes_registro_miembros
  WHERE id = p_solicitud_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Solicitud no encontrada';
  END IF;
  IF v_solicitud.estado_solicitud <> 'pendiente' THEN
    RAISE EXCEPTION 'La solicitud ya fue revisada';
  END IF;
  IF v_solicitud.email IS NULL OR v_solicitud.auth_user_id IS NULL THEN
    RAISE EXCEPTION 'La solicitud no tiene una cuenta Auth vinculada';
  END IF;

  SELECT id INTO v_perfil_id
  FROM public.perfiles_app
  WHERE id = v_solicitud.auth_user_id
    AND rol = 'hermano'
    AND activo = false
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
      activo = true,
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

REVOKE ALL ON FUNCTION public.crear_perfil_pendiente_renacer() FROM PUBLIC, anon, authenticated;

COMMIT;
