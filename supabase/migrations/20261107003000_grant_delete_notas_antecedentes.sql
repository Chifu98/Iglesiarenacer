GRANT DELETE ON TABLE public.notas_antecedentes TO authenticated;

-- La política RLS notas_antecedentes_delete ya limita las filas:
-- Admin: todas las notas.
-- Pastor: solo notas pastorales (incluidas las creadas por Admin).
-- Líder: notas propias y notas creadas por Admin dentro de sus ministerios autorizados.
