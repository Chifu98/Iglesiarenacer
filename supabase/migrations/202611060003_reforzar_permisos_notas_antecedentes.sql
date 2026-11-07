-- Completa el rol visible en notas históricas cuando falte.
UPDATE public.notas_antecedentes n
SET autor_rol = COALESCE(
  NULLIF(array_to_string(NULLIF(p.roles, ARRAY[]::text[]), ' / '), ''),
  NULLIF(p.rol, ''),
  'Usuario'
)
FROM public.perfiles_app p
WHERE p.id = n.autor_id
  AND (n.autor_rol IS NULL OR btrim(n.autor_rol) = '');

DROP POLICY IF EXISTS notas_antecedentes_select ON public.notas_antecedentes;
CREATE POLICY notas_antecedentes_select
ON public.notas_antecedentes
FOR SELECT
TO authenticated
USING (
  (
    tipo = 'pastoral'
    AND (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor'))
  )
  OR
  (
    tipo = 'lider'
    AND (
      public.app_tiene_rol_exacto('admin')
      OR public.app_tiene_rol_exacto('pastor')
      OR (
        public.app_tiene_rol_exacto('lider')
        AND private.app_lider_puede_ver_miembro(miembro_id)
        AND (
          autor_id = (SELECT auth.uid())
          OR autor_rol ~ '(^| / )admin($| / )'
          OR EXISTS (
            SELECT 1
            FROM public.perfiles_app autor
            WHERE autor.id = notas_antecedentes.autor_id
              AND (autor.roles @> ARRAY['admin']::text[] OR autor.rol = 'admin')
          )
        )
      )
    )
  )
);

DROP POLICY IF EXISTS notas_antecedentes_delete ON public.notas_antecedentes;
CREATE POLICY notas_antecedentes_delete
ON public.notas_antecedentes
FOR DELETE
TO authenticated
USING (
  (
    tipo = 'pastoral'
    AND (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor'))
  )
  OR
  (
    tipo = 'lider'
    AND (
      public.app_tiene_rol_exacto('admin')
      OR (
        public.app_tiene_rol_exacto('lider')
        AND private.app_lider_puede_ver_miembro(miembro_id)
        AND (
          autor_id = (SELECT auth.uid())
          OR autor_rol ~ '(^| / )admin($| / )'
          OR EXISTS (
            SELECT 1
            FROM public.perfiles_app autor
            WHERE autor.id = notas_antecedentes.autor_id
              AND (autor.roles @> ARRAY['admin']::text[] OR autor.rol = 'admin')
          )
        )
      )
    )
  )
);
