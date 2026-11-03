-- Habilitar sincronización Realtime para las tablas de Iglesia Renacer.
-- Script idempotente: puede ejecutarse más de una vez sin duplicar tablas en la publicación.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime'
      AND schemaname = 'public'
      AND tablename = 'miembros_app'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.miembros_app;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime'
      AND schemaname = 'public'
      AND tablename = 'peticiones_oracion'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE public.peticiones_oracion;
  END IF;
END $$;
