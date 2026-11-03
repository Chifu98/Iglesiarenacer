-- Renacer: ajuste de rendimiento RLS e índice duplicado de notas de líderes.
BEGIN;

-- Si la PK ya garantiza (miembro_id, lider_id), el índice adicional es redundante.
DO $$
DECLARE
  pk_cols text[];
BEGIN
  SELECT array_agg(a.attname ORDER BY u.ord)
  INTO pk_cols
  FROM pg_constraint c
  JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS u(attnum, ord) ON true
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = u.attnum
  WHERE c.conrelid = 'public.notas_lideres'::regclass
    AND c.contype = 'p'
  GROUP BY c.conname;

  IF pk_cols = ARRAY['miembro_id','lider_id']::text[] THEN
    DROP INDEX IF EXISTS public.notas_lideres_miembro_lider_uidx;
  END IF;
END;
$$;

DROP POLICY IF EXISTS notas_lideres_select_privado ON public.notas_lideres;
DROP POLICY IF EXISTS notas_lideres_insert_privado ON public.notas_lideres;
DROP POLICY IF EXISTS notas_lideres_update_privado ON public.notas_lideres;
DROP POLICY IF EXISTS notas_lideres_delete_privado ON public.notas_lideres;

CREATE POLICY notas_lideres_select_privado
ON public.notas_lideres FOR SELECT TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = (SELECT auth.uid()))
);

CREATE POLICY notas_lideres_insert_privado
ON public.notas_lideres FOR INSERT TO authenticated
WITH CHECK (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = (SELECT auth.uid()))
);

CREATE POLICY notas_lideres_update_privado
ON public.notas_lideres FOR UPDATE TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = (SELECT auth.uid()))
)
WITH CHECK (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = (SELECT auth.uid()))
);

CREATE POLICY notas_lideres_delete_privado
ON public.notas_lideres FOR DELETE TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR (public.app_tiene_rol('lider') AND lider_id = (SELECT auth.uid()))
);

COMMIT;
