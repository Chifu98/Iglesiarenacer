-- Historial de antecedentes pastorales y de líderes con autor y fecha.
BEGIN;
CREATE TABLE IF NOT EXISTS public.notas_antecedentes (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 miembro_id text NOT NULL REFERENCES public.miembros_app(id) ON DELETE CASCADE,
 tipo text NOT NULL CHECK (tipo IN ('pastoral','lider')),
 contenido text NOT NULL CHECK (length(btrim(contenido)) BETWEEN 1 AND 10000),
 autor_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
 autor_nombre text NOT NULL DEFAULT 'Registro histórico',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notas_antecedentes_miembro_tipo_fecha_idx
 ON public.notas_antecedentes(miembro_id,tipo,created_at DESC);
ALTER TABLE public.notas_antecedentes ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.notas_antecedentes FROM PUBLIC,anon,authenticated;
GRANT SELECT,INSERT ON TABLE public.notas_antecedentes TO authenticated;

CREATE OR REPLACE FUNCTION private.preparar_nota_antecedente()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE v_nombre text;
BEGIN
 IF auth.uid() IS NOT NULL
    AND COALESCE(current_setting('app.renacer_restore_antecedents',true),'false') <> 'true' THEN
  SELECT p.nombre INTO v_nombre FROM public.perfiles_app p
  WHERE p.id=auth.uid() AND p.activo=true;
  IF v_nombre IS NULL THEN RAISE EXCEPTION 'Se requiere un perfil activo para registrar una nota.'; END IF;
  NEW.autor_id:=auth.uid();
  NEW.autor_nombre:=v_nombre;
  NEW.created_at:=now();
 END IF;
 RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION private.preparar_nota_antecedente() FROM PUBLIC,anon,authenticated;
DROP TRIGGER IF EXISTS notas_antecedentes_preparar ON public.notas_antecedentes;
CREATE TRIGGER notas_antecedentes_preparar
 BEFORE INSERT ON public.notas_antecedentes
 FOR EACH ROW EXECUTE FUNCTION private.preparar_nota_antecedente();

DROP POLICY IF EXISTS notas_antecedentes_select ON public.notas_antecedentes;
CREATE POLICY notas_antecedentes_select ON public.notas_antecedentes
 FOR SELECT TO authenticated
 USING (
  (tipo='pastoral' AND (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor')))
  OR
  (tipo='lider' AND (
    public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor')
    OR (
      public.app_tiene_rol_exacto('lider')
      AND private.app_ministerio_lider_actual() IS NOT NULL
      AND EXISTS (SELECT 1 FROM public.miembros_app m
        WHERE m.id=notas_antecedentes.miembro_id
          AND m.ministry=private.app_ministerio_lider_actual())
    )
  ))
);
DROP POLICY IF EXISTS notas_antecedentes_insert ON public.notas_antecedentes;
CREATE POLICY notas_antecedentes_insert ON public.notas_antecedentes
 FOR INSERT TO authenticated
 WITH CHECK (
  autor_id=(SELECT auth.uid())
  AND (
   (tipo='pastoral' AND (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor')))
   OR
   (tipo='lider' AND public.app_tiene_rol_exacto('lider')
    AND private.app_ministerio_lider_actual() IS NOT NULL
    AND EXISTS (SELECT 1 FROM public.miembros_app m
      WHERE m.id=notas_antecedentes.miembro_id
        AND m.ministry=private.app_ministerio_lider_actual())
   )
  )
);
-- Conserva el contenido anterior como primera entrada histórica.
INSERT INTO public.notas_antecedentes(miembro_id,tipo,contenido,autor_id,autor_nombre,created_at)
SELECT n.miembro_id,'pastoral',n.nota,n.updated_by,
       COALESCE(p.nombre,'Registro histórico'),COALESCE(n.updated_at,now())
FROM public.notas_pastorales n LEFT JOIN public.perfiles_app p ON p.id=n.updated_by
WHERE NULLIF(btrim(n.nota),'') IS NOT NULL
AND NOT EXISTS (SELECT 1 FROM public.notas_antecedentes a
 WHERE a.miembro_id=n.miembro_id AND a.tipo='pastoral'
 AND a.contenido=n.nota AND a.created_at=COALESCE(n.updated_at,now()));
INSERT INTO public.notas_antecedentes(miembro_id,tipo,contenido,autor_id,autor_nombre,created_at)
SELECT n.miembro_id,'lider',n.nota,n.updated_by,
       COALESCE(p.nombre,'Registro histórico'),COALESCE(n.updated_at,now())
FROM public.notas_lideres n LEFT JOIN public.perfiles_app p ON p.id=n.updated_by
WHERE NULLIF(btrim(n.nota),'') IS NOT NULL
AND NOT EXISTS (SELECT 1 FROM public.notas_antecedentes a
 WHERE a.miembro_id=n.miembro_id AND a.tipo='lider'
 AND a.contenido=n.nota AND a.created_at=COALESCE(n.updated_at,now()));
 
CREATE OR REPLACE FUNCTION public.restaurar_antecedentes_respaldo(p_rows jsonb)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $
DECLARE v_rows bigint:=0;
BEGIN
 IF auth.uid() IS NULL OR NOT public.app_tiene_rol_exacto('admin') THEN
  RAISE EXCEPTION 'Solo un administrador puede restaurar antecedentes.';
 END IF;
 IF p_rows IS NULL OR jsonb_typeof(p_rows)<>'array' THEN
  RAISE EXCEPTION 'La colección de antecedentes no tiene formato de lista.';
 END IF;
 PERFORM set_config('app.renacer_restore_antecedents','true',true);
 INSERT INTO public.notas_antecedentes(id,miembro_id,tipo,contenido,autor_id,autor_nombre,created_at)
 SELECT id,miembro_id,tipo,contenido,autor_id,autor_nombre,created_at
 FROM jsonb_populate_recordset(NULL::public.notas_antecedentes,p_rows)
 ON CONFLICT(id) DO UPDATE SET
  miembro_id=EXCLUDED.miembro_id,tipo=EXCLUDED.tipo,contenido=EXCLUDED.contenido,
  autor_id=EXCLUDED.autor_id,autor_nombre=EXCLUDED.autor_nombre,created_at=EXCLUDED.created_at;
 GET DIAGNOSTICS v_rows=ROW_COUNT;
 RETURN v_rows;
END; $;
REVOKE ALL ON FUNCTION public.restaurar_antecedentes_respaldo(jsonb) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.restaurar_antecedentes_respaldo(jsonb) TO authenticated;

COMMENT ON TABLE public.notas_antecedentes IS 'Historial inmutable de antecedentes pastorales y de líderes con autor y fecha.';
COMMIT;