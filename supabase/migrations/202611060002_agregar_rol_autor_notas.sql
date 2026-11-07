ALTER TABLE public.notas_antecedentes
  ADD COLUMN IF NOT EXISTS autor_rol text;

UPDATE public.notas_antecedentes n
SET autor_rol = COALESCE(
  NULLIF(array_to_string(p.roles, ' / '), ''),
  NULLIF(p.rol, ''),
  'Usuario'
)
FROM public.perfiles_app p
WHERE p.id = n.autor_id
  AND (n.autor_rol IS NULL OR btrim(n.autor_rol) = '');

CREATE OR REPLACE FUNCTION private.preparar_nota_antecedente()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $function$
DECLARE
  v_nombre text;
  v_rol text;
BEGIN
  IF auth.uid() IS NOT NULL
     AND COALESCE(current_setting('app.renacer_restore_antecedents', true), 'false') <> 'true' THEN
    SELECT
      p.nombre,
      COALESCE(NULLIF(array_to_string(p.roles, ' / '), ''), NULLIF(p.rol, ''), 'Usuario')
    INTO v_nombre, v_rol
    FROM public.perfiles_app p
    WHERE p.id = auth.uid() AND p.activo = true;

    IF v_nombre IS NULL THEN
      RAISE EXCEPTION 'Se requiere un perfil activo para registrar una nota.';
    END IF;

    NEW.autor_id := auth.uid();
    NEW.autor_nombre := v_nombre;
    NEW.autor_rol := v_rol;
    NEW.created_at := now();
  END IF;
  RETURN NEW;
END;
$function$;