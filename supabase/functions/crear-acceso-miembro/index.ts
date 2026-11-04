import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.8";

const cors = {
  "Access-Control-Allow-Origin": "https://iglesiarenacer.vercel.app",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Método no permitido." }, 405);
  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return json({ error: "No autenticado." }, 401);

  const url = Deno.env.get("SUPABASE_URL")!;
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const callerClient = createClient(url, anonKey, { global: { headers: { Authorization: authHeader } }, auth: { persistSession: false } });
  const adminClient = createClient(url, serviceKey, { auth: { persistSession: false } });

  try {
    const { data: callerData, error: callerError } = await callerClient.auth.getUser();
    if (callerError || !callerData.user) return json({ error: "Sesión no válida." }, 401);
    const { data: callerProfile, error: profileError } = await adminClient
      .from("perfiles_app").select("id,roles,rol,activo").eq("id", callerData.user.id).maybeSingle();
    if (profileError) throw profileError;
    const roles = Array.isArray(callerProfile?.roles) ? callerProfile.roles : [callerProfile?.rol];
    if (!callerProfile?.activo || !roles.includes("admin")) return json({ error: "Solo administradores pueden crear accesos." }, 403);

    const payload = await req.json();
    const memberId = String(payload.member_id || "").trim();
    if (!memberId) return json({ error: "Falta el identificador de la ficha." }, 400);
    const { data: member, error: memberError } = await adminClient
      .from("miembros_app").select("id,name,email,status").eq("id", memberId).maybeSingle();
    if (memberError) throw memberError;
    if (!member) return json({ error: "No se encontró la ficha." }, 404);
    if (member.status !== "Activo") return json({ error: "La ficha debe tener estado Activo antes de crear el acceso." }, 409);
    const email = String(member.email || "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Registra un correo electrónico válido en la ficha." }, 400);

    const { data: duplicateMember, error: duplicateMemberError } = await adminClient
      .from("miembros_app").select("id").ilike("email", email).neq("id", memberId).limit(1).maybeSingle();
    if (duplicateMemberError) throw duplicateMemberError;
    if (duplicateMember) return json({ error: "Este correo también figura en otra ficha. Corrige el duplicado antes de habilitar el acceso." }, 409);

    const { data: linkedProfile, error: linkedError } = await adminClient
      .from("perfiles_app").select("id,miembro_id,usuario").eq("miembro_id", memberId).maybeSingle();
    if (linkedError) throw linkedError;
    if (linkedProfile) return json({ status: "already_linked", email, message: "Esta ficha ya tiene una cuenta vinculada." });

    const { data: emailProfile, error: emailProfileError } = await adminClient
      .from("perfiles_app").select("id,miembro_id,activo").ilike("usuario", email).maybeSingle();
    if (emailProfileError) throw emailProfileError;

    let authUser: { id: string; email?: string } | null = null;
    const { data: userPage, error: listError } = await adminClient.auth.admin.listUsers({ page: 1, perPage: 1000 });
    if (listError) throw listError;
    authUser = userPage.users.find((u) => (u.email || "").toLowerCase() === email) || null;

    if (emailProfile && (!authUser || emailProfile.id !== authUser.id)) {
      return json({ error: "El correo ya está asociado a otro perfil. Revisa la vinculación antes de continuar." }, 409);
    }
    if (emailProfile?.miembro_id && emailProfile.miembro_id !== memberId) {
      return json({ error: "Esta cuenta ya está vinculada a otra ficha congregacional." }, 409);
    }

    if (!authUser) {
      const { data: created, error: createError } = await adminClient.auth.admin.createUser({
        email,
        email_confirm: true,
        app_metadata: { renacer_admin_provisioned: "true", renacer_member_id: memberId },
      });
      if (createError) throw createError;
      authUser = created.user;
    } else {
      const { data: existingProfile, error: existingError } = await adminClient
        .from("perfiles_app").select("id,miembro_id,rol,roles").eq("id", authUser.id).maybeSingle();
      if (existingError) throw existingError;
      if (existingProfile?.miembro_id && existingProfile.miembro_id !== memberId) {
        return json({ error: "La cuenta ya está vinculada a otra ficha congregacional." }, 409);
      }
      const existingRoles = Array.isArray(existingProfile?.roles)
        ? existingProfile.roles
        : (existingProfile?.rol ? [existingProfile.rol] : []);
      const profilePayload = {
        nombre: member.name,
        usuario: email,
        rol: existingProfile?.rol || "miembro",
        roles: Array.from(new Set([...existingRoles, "miembro"])),
        activo: true,
        estado_solicitud: "aprobado",
        miembro_id: memberId,
      };
      const { error: upsertError } = await adminClient.from("perfiles_app")
        .upsert({ id: authUser.id, ...profilePayload }, { onConflict: "id" });
      if (upsertError) throw upsertError;
    }

    return json({
      status: "ready",
      email,
      message: "Acceso creado y vinculado. Envía ahora el enlace seguro para establecer la contraseña.",
    });
  } catch (error) {
    console.error("crear-acceso-miembro:", error);
    return json({ error: error instanceof Error ? error.message : "No se pudo crear el acceso." }, 500);
  }
});
