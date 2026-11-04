DROP POLICY IF EXISTS registro_publico_intentos_deny_all ON public.registro_publico_intentos;
CREATE POLICY registro_publico_intentos_deny_all
ON public.registro_publico_intentos
FOR ALL TO anon, authenticated
USING (false)
WITH CHECK (false);
