-- Iglesia Renacer: endurecimiento de privilegios y RLS
-- Fecha: 2026-11-03
-- Ejecutar manualmente en Supabase SQL Editor después de respaldar la BD.
-- No modifica filas ni cambia roles existentes.

BEGIN;

-- 1) La tabla heredada public.miembros:
-- lectura para cuentas activas; escritura solo para Admin/Escritura
-- (app_tiene_rol('escritura') incluye Pastor, Servidor y Líder).
ALTER TABLE public.miembros ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE p record;
BEGIN
  FOR p IN
    SELECT policyname
    FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'miembros'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.miembros', p.policyname);
  END LOOP;
END
$$;

CREATE POLICY miembros_select_usuarios_activos
ON public.miembros
FOR SELECT TO authenticated
USING (public.app_tiene_rol('hermano'));

CREATE POLICY miembros_insert_gestores
ON public.miembros
FOR INSERT TO authenticated
WITH CHECK (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('escritura')
);

CREATE POLICY miembros_update_gestores
ON public.miembros
FOR UPDATE TO authenticated
USING (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('escritura')
)
WITH CHECK (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('escritura')
);

CREATE POLICY miembros_delete_gestores
ON public.miembros
FOR DELETE TO authenticated
USING (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('escritura')
);

-- 2) Quitar privilegios SQL innecesarios de anon y privilegios DDL-like
-- (TRUNCATE, REFERENCES, TRIGGER) de authenticated en tablas de la app.
REVOKE ALL PRIVILEGES ON TABLE
  public.anuncios,
  public.avisos_congregacion,
  public.miembros,
  public.miembros_app,
  public.notas_lideres,
  public.notas_pastorales,
  public.perfiles_app,
  public.peticiones_oracion,
  public.registro_auditoria,
  public.solicitudes_registro_miembros,
  public.suscripciones_push
FROM anon;

REVOKE ALL PRIVILEGES ON TABLE
  public.anuncios,
  public.avisos_congregacion,
  public.miembros,
  public.miembros_app,
  public.notas_lideres,
  public.notas_pastorales,
  public.perfiles_app,
  public.peticiones_oracion,
  public.registro_auditoria,
  public.solicitudes_registro_miembros,
  public.suscripciones_push
FROM authenticated;

-- 3) Reasignar únicamente los privilegios DML que necesita el frontend.
-- RLS sigue siendo la barrera de autorización fila por fila.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.anuncios,
  public.avisos_congregacion,
  public.miembros,
  public.miembros_app,
  public.notas_lideres,
  public.notas_pastorales,
  public.peticiones_oracion,
  public.suscripciones_push
TO authenticated;

GRANT SELECT, UPDATE ON TABLE public.perfiles_app TO authenticated;
GRANT SELECT ON TABLE public.registro_auditoria TO authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.solicitudes_registro_miembros TO authenticated;

-- El formulario público solo necesita crear solicitudes; RLS valida los campos.
GRANT INSERT ON TABLE public.solicitudes_registro_miembros TO anon;

-- 4) Refuerzo explícito de políticas de notas.
-- Incluimos tablename en el SELECT para poder referirnos a p.tablename.
DO $$
DECLARE p record;
BEGIN
  FOR p IN
    SELECT policyname, tablename
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename IN ('notas_lideres', 'notas_pastorales')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', p.policyname, p.tablename);
  END LOOP;
END
$$;

CREATE POLICY notas_lideres_select
ON public.notas_lideres FOR SELECT TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR public.app_tiene_rol('lider')
);
CREATE POLICY notas_lideres_insert
ON public.notas_lideres FOR INSERT TO authenticated
WITH CHECK (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR public.app_tiene_rol('lider')
);
CREATE POLICY notas_lideres_update
ON public.notas_lideres FOR UPDATE TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR public.app_tiene_rol('lider')
)
WITH CHECK (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR public.app_tiene_rol('lider')
);
CREATE POLICY notas_lideres_delete
ON public.notas_lideres FOR DELETE TO authenticated
USING (
  public.app_tiene_rol('admin')
  OR public.app_tiene_rol('pastor')
  OR public.app_tiene_rol('lider')
);

CREATE POLICY notas_pastorales_select
ON public.notas_pastorales FOR SELECT TO authenticated
USING (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor')
);
CREATE POLICY notas_pastorales_insert
ON public.notas_pastorales FOR INSERT TO authenticated
WITH CHECK (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor')
);
CREATE POLICY notas_pastorales_update
ON public.notas_pastorales FOR UPDATE TO authenticated
USING (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor')
)
WITH CHECK (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor')
);
CREATE POLICY notas_pastorales_delete
ON public.notas_pastorales FOR DELETE TO authenticated
USING (
  public.app_tiene_rol('admin') OR public.app_tiene_rol('pastor')
);

-- 5) Endurecer función de cumpleaños y auditar notas de líderes.
CREATE OR REPLACE FUNCTION public.listar_cumpleanos_congregacion()
RETURNS TABLE(nombre text, cumpleanos text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF auth.uid() IS NULL OR NOT public.app_tiene_rol('hermano') THEN
    RAISE EXCEPTION 'Solo los hermanos con acceso aprobado pueden consultar los cumpleaños.';
  END IF;

  RETURN QUERY
  SELECT m.name, to_char(m.birthday, 'DD/MM')
  FROM public.miembros_app AS m
  WHERE m.status = 'Activo'
    AND m.birthday IS NOT NULL
  ORDER BY EXTRACT(MONTH FROM m.birthday),
           EXTRACT(DAY FROM m.birthday),
           m.name;
END;
$$;

REVOKE ALL ON FUNCTION public.listar_cumpleanos_congregacion() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.listar_cumpleanos_congregacion() TO authenticated;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_trigger
    WHERE tgname = 'auditoria_notas_lideres'
      AND tgrelid = 'public.notas_lideres'::regclass
      AND NOT tgisinternal
  ) THEN
    CREATE TRIGGER auditoria_notas_lideres
    AFTER INSERT OR UPDATE OR DELETE ON public.notas_lideres
    FOR EACH ROW
    EXECUTE FUNCTION public.registrar_evento_auditoria_renacer();
  END IF;
END
$$;

COMMIT;

-- NOTAS:
-- * No se fuerza RLS porque requiere revisar los propietarios/roles de servicio.
-- * No se cambia la visibilidad pública del bucket profile-photos.
-- * No se revocan permisos de storage.objects: el registro público necesita subir
--   fotos al directorio pending según la política existente.
-- * La tabla public.miembros se protege con roles de la app; verificar si alguna
--   integración antigua la utiliza después de aplicar la migración.
