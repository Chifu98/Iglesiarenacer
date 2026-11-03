-- Suscripciones Web Push: avisos únicamente para anuncios congregacionales.
BEGIN;

CREATE TABLE IF NOT EXISTS public.suscripciones_push (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  endpoint text NOT NULL UNIQUE,
  p256dh text NOT NULL,
  auth text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.suscripciones_push ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS suscripciones_push_select_own ON public.suscripciones_push;
DROP POLICY IF EXISTS suscripciones_push_insert_own ON public.suscripciones_push;
DROP POLICY IF EXISTS suscripciones_push_update_own ON public.suscripciones_push;
DROP POLICY IF EXISTS suscripciones_push_delete_own ON public.suscripciones_push;

CREATE POLICY suscripciones_push_select_own ON public.suscripciones_push
FOR SELECT TO authenticated USING (usuario_id = auth.uid());

CREATE POLICY suscripciones_push_insert_own ON public.suscripciones_push
FOR INSERT TO authenticated WITH CHECK (usuario_id = auth.uid());

CREATE POLICY suscripciones_push_update_own ON public.suscripciones_push
FOR UPDATE TO authenticated USING (usuario_id = auth.uid())
WITH CHECK (usuario_id = auth.uid());

CREATE POLICY suscripciones_push_delete_own ON public.suscripciones_push
FOR DELETE TO authenticated USING (usuario_id = auth.uid());

GRANT SELECT, INSERT, UPDATE, DELETE ON public.suscripciones_push TO authenticated;
REVOKE ALL ON public.suscripciones_push FROM anon;

COMMIT;
