BEGIN;
INSERT INTO storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
VALUES ('profile-photos','profile-photos',true,2097152,ARRAY['image/jpeg','image/png','image/webp','image/gif'])
ON CONFLICT (id) DO UPDATE SET public=true,file_size_limit=2097152,allowed_mime_types=ARRAY['image/jpeg','image/png','image/webp','image/gif'];
DROP POLICY IF EXISTS profile_photos_pending_upload ON storage.objects;
CREATE POLICY profile_photos_pending_upload ON storage.objects FOR INSERT TO anon
WITH CHECK (bucket_id='profile-photos' AND (storage.foldername(name))[1]='pending');
DROP POLICY IF EXISTS profile_photos_user_upload ON storage.objects;
CREATE POLICY profile_photos_user_upload ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id='profile-photos' AND (storage.foldername(name))[1]='users' AND (storage.foldername(name))[2]=auth.uid()::text);
CREATE OR REPLACE FUNCTION public.aplicar_foto_solicitud_miembro()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE requested_avatar text;
BEGIN
 IF NEW.avatar IS NULL OR btrim(NEW.avatar)='' THEN
  SELECT NULLIF(u.raw_user_meta_data->>'avatar_url','') INTO requested_avatar
  FROM auth.users u WHERE lower(u.email)=lower(NEW.email) ORDER BY u.created_at DESC LIMIT 1;
  IF requested_avatar IS NOT NULL AND requested_avatar LIKE '%/storage/v1/object/public/profile-photos/pending/%' THEN NEW.avatar:=requested_avatar; END IF;
 END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS trigger_aplicar_foto_solicitud_miembro ON public.miembros_app;
CREATE TRIGGER trigger_aplicar_foto_solicitud_miembro BEFORE INSERT OR UPDATE OF email ON public.miembros_app
FOR EACH ROW EXECUTE FUNCTION public.aplicar_foto_solicitud_miembro();
CREATE OR REPLACE FUNCTION public.actualizar_mi_foto(p_avatar_url text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE linked_member_id text;
BEGIN
 IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Debes iniciar sesión para cambiar tu fotografía.'; END IF;
 IF p_avatar_url IS NULL OR p_avatar_url !~ ('/storage/v1/object/public/profile-photos/users/' || auth.uid()::text || '/[^ ]+$') THEN
  RAISE EXCEPTION 'La ruta de la fotografía no es válida para esta cuenta.';
 END IF;
 SELECT p.miembro_id::text INTO linked_member_id FROM public.perfiles_app p WHERE p.id=auth.uid() AND p.activo=true;
 IF linked_member_id IS NULL THEN RAISE EXCEPTION 'Tu cuenta no tiene una ficha de miembro vinculada.'; END IF;
 UPDATE public.miembros_app SET avatar=p_avatar_url,updated_at=now() WHERE id::text=linked_member_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'No se encontró tu ficha de miembro.'; END IF;
END; $$;
REVOKE ALL ON FUNCTION public.actualizar_mi_foto(text) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.actualizar_mi_foto(text) TO authenticated;
COMMIT;