-- El rol Servidor puede crear fichas únicamente en estado "En Visita".
-- Admin y Pastor conservan permisos completos. Líder conserva su gestión,
-- excepto cuando la cuenta también tiene el rol Servidor (salvo Admin/Pastor).
DROP POLICY IF EXISTS miembros_app_insert_gestores ON public.miembros_app;
CREATE POLICY miembros_app_insert_gestores
ON public.miembros_app
FOR INSERT
TO authenticated
WITH CHECK (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
  OR (
    public.app_tiene_rol_exacto('lider')
    AND NOT public.app_tiene_rol_exacto('servidor')
  )
  OR (
    public.app_tiene_rol_exacto('servidor')
    AND status = 'En Visita'
  )
);

DROP POLICY IF EXISTS miembros_app_update_gestores ON public.miembros_app;
CREATE POLICY miembros_app_update_gestores
ON public.miembros_app
FOR UPDATE
TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
  OR (
    public.app_tiene_rol_exacto('lider')
    AND NOT public.app_tiene_rol_exacto('servidor')
  )
)
WITH CHECK (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
  OR (
    public.app_tiene_rol_exacto('lider')
    AND NOT public.app_tiene_rol_exacto('servidor')
  )
);

DROP POLICY IF EXISTS miembros_app_delete_gestores ON public.miembros_app;
CREATE POLICY miembros_app_delete_gestores
ON public.miembros_app
FOR DELETE
TO authenticated
USING (
  public.app_tiene_rol_exacto('admin')
  OR public.app_tiene_rol_exacto('pastor')
  OR (
    public.app_tiene_rol_exacto('lider')
    AND NOT public.app_tiene_rol_exacto('servidor')
  )
);
