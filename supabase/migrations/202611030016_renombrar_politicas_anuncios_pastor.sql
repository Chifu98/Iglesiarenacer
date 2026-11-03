-- Renacer: aclarar nombres de políticas tras sustituir Escritura por Pastor.
BEGIN;
ALTER POLICY anuncios_insert_admin_escritura ON public.anuncios RENAME TO anuncios_insert_admin_pastor;
ALTER POLICY anuncios_update_admin_escritura ON public.anuncios RENAME TO anuncios_update_admin_pastor;
ALTER POLICY anuncios_delete_admin_escritura ON public.anuncios RENAME TO anuncios_delete_admin_pastor;
COMMIT;