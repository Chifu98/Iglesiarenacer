import webpush from "npm:web-push@3.6.7";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const vapidPublic = Deno.env.get("VAPID_PUBLIC_KEY")!;
    const vapidPrivate = Deno.env.get("VAPID_PRIVATE_KEY")!;
    const vapidSubject = Deno.env.get("VAPID_SUBJECT") || "mailto:admin@iglesiarenacer.cl";

    const authHeader = req.headers.get("Authorization") || "";
    if (!authHeader.startsWith("Bearer ")) return json({ error: "Unauthorized" }, 401);

    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: userData, error: userError } = await userClient.auth.getUser();
    if (userError || !userData.user) return json({ error: "Unauthorized" }, 401);

    const admin = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: profile, error: profileError } = await admin
      .from("perfiles_app")
      .select("id,activo,roles,rol")
      .eq("id", userData.user.id)
      .maybeSingle();

    if (profileError || !profile?.activo) return json({ error: "Forbidden" }, 403);
    const roles = Array.isArray(profile.roles) ? profile.roles : (profile.rol ? [profile.rol] : []);
    // Roles independientes: solo admin o escritura pueden publicar anuncios.
    const allowed = roles.includes("admin") || roles.includes("escritura");
    if (!allowed) return json({ error: "Forbidden" }, 403);

    const body = await req.json();
    const title = String(body.title || "").trim().slice(0, 120);
    const content = String(body.content || "").trim().slice(0, 240);
    if (title.length < 3 || content.length < 3) {
      return json({ error: "Invalid announcement payload" }, 400);
    }

    webpush.setVapidDetails(vapidSubject, vapidPublic, vapidPrivate);
    const { data: subscriptions, error: subscriptionsError } = await admin
      .from("suscripciones_push")
      .select("id,usuario_id,endpoint,p256dh,auth")
      .neq("usuario_id", userData.user.id);

    if (subscriptionsError) throw subscriptionsError;

    const payload = JSON.stringify({
      title: "Iglesia Renacer · " + title,
      body: content,
      url: "/",
      tag: "renacer-announcement",
    });

    let sent = 0;
    let failed = 0;
    const expired: string[] = [];

    await Promise.all((subscriptions || []).map(async (row) => {
      try {
        await webpush.sendNotification({
          endpoint: row.endpoint,
          keys: { p256dh: row.p256dh, auth: row.auth },
        }, payload, { TTL: 60 * 60 * 24 });
        sent++;
      } catch (error) {
        failed++;
        const statusCode = (error as { statusCode?: number }).statusCode;
        if (statusCode === 404 || statusCode === 410) expired.push(row.endpoint);
        console.error("Push delivery failed", statusCode || error);
      }
    }));

    if (expired.length) {
      await admin.from("suscripciones_push").delete().in("endpoint", expired);
    }

    return json({ sent, failed, removedExpired: expired.length });
  } catch (error) {
    console.error("send-announcement-push error:", error);
    return json({ error: "No se pudieron enviar los avisos." }, 500);
  }
});
