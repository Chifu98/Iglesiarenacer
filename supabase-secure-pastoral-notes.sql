-- IGLESIA RENACER: proteger notas pastorales
-- Ejecutar una sola vez en Supabase > SQL Editor.
-- Copia notas existentes antes de retirar la columna pública de miembros_app.

BEGIN;

CREATE TABLE IF NOT EXISTS public.notas_pastorales (
    miembro_id TEXT PRIMARY KEY
        REFERENCES public.miembros_app(id) ON DELETE CASCADE,
    nota TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL
);

-- Migrar las notas actuales, si la columna existe.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'miembros_app'
          AND column_name = 'notes'
    ) THEN
        INSERT INTO public.notas_pastorales (miembro_id, nota)
        SELECT id, COALESCE(notes, '')
        FROM public.miembros_app
        WHERE notes IS NOT NULL AND BTRIM(notes) <> ''
        ON CONFLICT (miembro_id)
        DO UPDATE SET nota = EXCLUDED.nota,
                      updated_at = NOW();
    END IF;
END $$;

ALTER TABLE public.notas_pastorales ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.notas_pastorales FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE
ON public.notas_pastorales TO authenticated;

DROP POLICY IF EXISTS "notas_admin_select"
ON public.notas_pastorales;
CREATE POLICY "notas_admin_select"
ON public.notas_pastorales
FOR SELECT TO authenticated
USING (public.app_rol_actual() = 'admin');

DROP POLICY IF EXISTS "notas_admin_insert"
ON public.notas_pastorales;
CREATE POLICY "notas_admin_insert"
ON public.notas_pastorales
FOR INSERT TO authenticated
WITH CHECK (public.app_rol_actual() = 'admin');

DROP POLICY IF EXISTS "notas_admin_update"
ON public.notas_pastorales;
CREATE POLICY "notas_admin_update"
ON public.notas_pastorales
FOR UPDATE TO authenticated
USING (public.app_rol_actual() = 'admin')
WITH CHECK (public.app_rol_actual() = 'admin');

DROP POLICY IF EXISTS "notas_admin_delete"
ON public.notas_pastorales;
CREATE POLICY "notas_admin_delete"
ON public.notas_pastorales
FOR DELETE TO authenticated
USING (public.app_rol_actual() = 'admin');

-- Importante: solo después de copiar los datos se elimina la columna que antes
-- permitía que cualquier perfil con lectura de miembros consultara las notas.
ALTER TABLE public.miembros_app
DROP COLUMN IF EXISTS notes;

COMMIT;
