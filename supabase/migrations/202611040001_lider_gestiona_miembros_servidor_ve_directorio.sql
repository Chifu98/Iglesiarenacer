-- Permisos de directorio para lideres y servidores.
DROP POLICY IF EXISTS miembros_select_autorizados ON public.miembros;
CREATE POLICY miembros_select_autorizados ON public.miembros FOR SELECT TO authenticated
USING (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider') OR public.app_tiene_rol_exacto('servidor'));

DROP POLICY IF EXISTS miembros_insert_gestores ON public.miembros;
CREATE POLICY miembros_insert_gestores ON public.miembros FOR INSERT TO authenticated
WITH CHECK (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider') OR public.app_tiene_rol_exacto('servidor'));

DROP POLICY IF EXISTS miembros_update_gestores ON public.miembros;
CREATE POLICY miembros_update_gestores ON public.miembros FOR UPDATE TO authenticated
USING (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider'))
WITH CHECK (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider'));

DROP POLICY IF EXISTS miembros_delete_gestores ON public.miembros;
CREATE POLICY miembros_delete_gestores ON public.miembros FOR DELETE TO authenticated
USING (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider'));

DROP POLICY IF EXISTS miembros_app_select_privacidad ON public.miembros_app;
DROP POLICY IF EXISTS miembros_app_select_servidor_propios ON public.miembros_app;
CREATE POLICY miembros_app_select_privacidad ON public.miembros_app FOR SELECT TO authenticated
USING (
 public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR
 public.app_tiene_rol_exacto('lider') OR public.app_tiene_rol_exacto('servidor') OR
 (public.app_tiene_rol_exacto('hermano') AND id = public.app_miembro_id_actual())
);

DROP POLICY IF EXISTS miembros_app_insert_gestores ON public.miembros_app;
CREATE POLICY miembros_app_insert_gestores ON public.miembros_app FOR INSERT TO authenticated
WITH CHECK (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider') OR public.app_tiene_rol_exacto('servidor'));

DROP POLICY IF EXISTS miembros_app_update_gestores ON public.miembros_app;
CREATE POLICY miembros_app_update_gestores ON public.miembros_app FOR UPDATE TO authenticated
USING (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider'))
WITH CHECK (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider'));

DROP POLICY IF EXISTS miembros_app_delete_gestores ON public.miembros_app;
CREATE POLICY miembros_app_delete_gestores ON public.miembros_app FOR DELETE TO authenticated
USING (public.app_tiene_rol_exacto('admin') OR public.app_tiene_rol_exacto('pastor') OR public.app_tiene_rol_exacto('lider'));
