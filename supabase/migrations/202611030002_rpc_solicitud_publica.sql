-- RPC segura para crear solicitudes públicas sin conceder SELECT a anon.
BEGIN;

CREATE OR REPLACE FUNCTION public.crear_solicitud_registro_miembro(
  p_name text,
  p_phone text,
  p_email text,
  p_address text,
  p_marital_status text,
  p_spouse_type text,
  p_spouse_name text,
  p_ministry text,
  p_baptized text,
  p_birthday date
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_id uuid;
BEGIN
  IF p_name IS NULL OR length(btrim(p_name)) < 3
     OR p_phone IS NULL OR length(btrim(p_phone)) < 7
     OR p_email IS NULL OR length(btrim(p_email)) < 5
     OR position('@' IN p_email) < 2
     OR p_birthday IS NULL THEN
    RAISE EXCEPTION 'Completa correctamente los campos obligatorios';
  END IF;

  IF p_spouse_type NOT IN ('none', 'text') THEN
    RAISE EXCEPTION 'Tipo de cónyuge no válido';
  END IF;

  INSERT INTO public.solicitudes_registro_miembros (
    name, phone, email, address, marital_status, spouse_type,
    spouse_name, spouse_id, ministry, baptized, birthday, status
  ) VALUES (
    btrim(p_name), btrim(p_phone), lower(btrim(p_email)),
    NULLIF(btrim(COALESCE(p_address, '')), ''),
    p_marital_status, p_spouse_type,
    NULLIF(btrim(COALESCE(p_spouse_name, '')), ''),
    NULL, p_ministry, p_baptized, p_birthday, 'Activo'
  )
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$;

REVOKE ALL ON FUNCTION public.crear_solicitud_registro_miembro(text,text,text,text,text,text,text,text,text,date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.crear_solicitud_registro_miembro(text,text,text,text,text,text,text,text,text,date) TO anon, authenticated;

COMMIT;
