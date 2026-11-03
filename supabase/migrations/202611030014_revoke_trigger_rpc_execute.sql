-- Renacer: una función de trigger no debe ser invocable directamente por clientes API.
BEGIN;
REVOKE ALL ON FUNCTION public.aplicar_foto_solicitud_miembro() FROM PUBLIC, anon, authenticated;
COMMIT;
