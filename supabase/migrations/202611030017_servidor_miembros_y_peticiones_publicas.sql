-- Permisos de creación de miembros para Servidor y peticiones congregacionales públicas
-- La lectura y publicación de peticiones aplica a todas las cuentas activas autenticadas.
ALTER TABLE public.peticiones_oracion
  ADD COLUMN IF NOT EXISTS member_name text;

DROP POLICY IF EXISTS miembros_app_insert_gestores ON public.miembros_app;
CREATE POLICY miembros_app_insert_gestores
  ON public.miembros_app
  FOR INSERT TO authenticated
  WITH CHECK (
    public.app_tiene_rol_exacto('admin')
    OR public.app_tiene_rol_exacto('pastor')
    OR public.app_tiene_rol_exacto('servidor')
  );

DROP POLICY IF EXISTS miembros_app_select_servidor_propios ON public.miembros_app;
CREATE POLICY miembros_app_select_servidor_propios
  ON public.miembros_app
  FOR SELECT TO authenticated
  USING (
    public.app_tiene_rol_exacto('servidor')
    AND created_by = (SELECT auth.uid())
  );

DROP POLICY IF EXISTS miembros_insert_gestores ON public.miembros;
CREATE POLICY miembros_insert_gestores
  ON public.miembros
  FOR INSERT TO authenticated
  WITH CHECK (
    public.app_tiene_rol_exacto('admin')
    OR public.app_tiene_rol_exacto('pastor')
    OR public.app_tiene_rol_exacto('servidor')
  );

DROP POLICY IF EXISTS peticiones_insert_propias ON public.peticiones_oracion;
CREATE POLICY peticiones_insert_usuarios_activos
  ON public.peticiones_oracion
  FOR INSERT TO authenticated
  WITH CHECK (
    created_by = (SELECT auth.uid())
    AND EXISTS (
      SELECT 1 FROM public.perfiles_app p
      WHERE p.id = (SELECT auth.uid()) AND p.activo = TRUE
    )
  );

DROP POLICY IF EXISTS peticiones_select_privacidad ON public.peticiones_oracion;
CREATE POLICY peticiones_select_usuarios_activos
  ON public.peticiones_oracion
  FOR SELECT TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.perfiles_app p
      WHERE p.id = (SELECT auth.uid()) AND p.activo = TRUE
    )
  );

DROP POLICY IF EXISTS peticiones_delete_gestores ON public.peticiones_oracion;
CREATE POLICY peticiones_delete_gestores
  ON public.peticiones_oracion
  FOR DELETE TO authenticated
  USING (
    public.app_tiene_rol_exacto('admin')
    OR public.app_tiene_rol_exacto('pastor')
    OR public.app_tiene_rol_exacto('lider')
    OR public.app_tiene_rol_exacto('servidor')
  );
