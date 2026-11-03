/* PORTAL PRIVADO DE HERMANOS - IGLESIA RENACER */
let memberPortalProfile = null;
let memberPortalPrayerRows = [];
let memberPortalAnnouncementRows = [];
let memberPortalBirthdayRows = [];
let memberPortalChannel = null;
let renacerAnnouncementRows = [];

const renacerBaseLoadData = loadData;
const renacerBaseShowLoginView = showLoginView;

showAccessOption = function(option) {
  const panels = {
    menu: "access-menu",
    servers: "server-access-panel",
    members: "member-entry-panel",
    "register-member": "public-member-panel",
    "member-login": "member-login-panel"
  };
  ["access-menu", "server-access-panel", "public-member-panel", "member-entry-panel", "member-login-panel"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("hidden", id !== (panels[option] || "access-menu"));
  });
  const error = document.getElementById("login-error");
  if (error) error.classList.add("hidden");
  const signup = document.getElementById("signup-form");
  if (signup && option !== "servers") signup.classList.add("hidden");
  if (window.lucide) lucide.createIcons();
};

showLoginView = function() {
  renacerBaseShowLoginView();
  const portal = document.getElementById("member-portal-container");
  if (portal) portal.classList.add("hidden");
};

function setPortalMessage(id, message, success=false) {
  const box = document.getElementById(id);
  if (!box) return;
  box.textContent = message;
  box.className = "p-3 rounded-xl text-xs " + (success
    ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-300"
    : "bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300");
}

async function handleMemberSignup(event) {
  event.preventDefault();
  const email = document.getElementById("member-signup-email").value.trim().toLowerCase();
  const password = document.getElementById("member-signup-password").value;
  if (!email || password.length < 8) {
    setPortalMessage("member-signup-message", "Ingresa el correo registrado y una contraseña de al menos 8 caracteres.");
    return;
  }
  const button = event.submitter || event.target.querySelector('button[type="submit"]');
  if (button) { button.disabled = true; button.textContent = "Enviando solicitud..."; }
  try {
    const { data, error } = await window.supabaseClient.auth.signUp({
      email,
      password,
      options: { data: { tipo_cuenta: "hermano" }, emailRedirectTo: window.location.origin }
    });
    if (error) throw error;
    if (data.session) await window.supabaseClient.auth.signOut();
    document.getElementById("member-signup-form").reset();
    setPortalMessage("member-signup-message", "Solicitud creada. Confirma tu correo si Supabase lo solicita. Un administrador debe aprobar tu acceso antes de que puedas ingresar.", true);
  } catch (error) {
    console.error("Error creando acceso de hermano:", error);
    setPortalMessage("member-signup-message", "No se pudo crear el acceso. Verifica que tu perfil congregacional esté aprobado y que el correo coincida exactamente con el registrado. Si el problema continúa, contacta a un administrador.");
  } finally {
    if (button) { button.disabled = false; button.textContent = "Solicitar acceso al portal"; }
  }
}

async function handleMemberLogin(event) {
  event.preventDefault();
  const email = document.getElementById("member-login-email").value.trim();
  const password = document.getElementById("member-login-password").value;
  const button = event.submitter || event.target.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const { error } = await window.supabaseClient.auth.signInWithPassword({ email, password });
    if (error) throw error;
    await loadData();
  } catch (error) {
    console.error("Error ingresando al portal:", error);
    setPortalMessage("member-login-message", "No se pudo ingresar. Verifica tus credenciales, confirma tu correo y asegúrate de que un administrador haya aprobado tu acceso.");
  } finally {
    if (button) button.disabled = false;
  }
}

async function handleMemberPasswordReset() {
  const email = document.getElementById("member-login-email").value.trim();
  if (!email) {
    setPortalMessage("member-login-message", "Escribe tu correo electrónico para recuperar la contraseña.");
    return;
  }
  const { error } = await window.supabaseClient.auth.resetPasswordForEmail(email, {
    redirectTo: new URL("restablecer.html", window.location.href).toString()
  });
  if (error) setPortalMessage("member-login-message", "No se pudo enviar el enlace: " + error.message);
  else setPortalMessage("member-login-message", "Te enviamos un enlace de recuperación. Revisa tu correo.", true);
}

loadData = async function() {
  const { data: sessionData, error: sessionError } = await window.supabaseClient.auth.getSession();
  if (sessionError) throw sessionError;
  const session = sessionData.session;
  if (!session) return renacerBaseLoadData();

  const { data: profile, error } = await window.supabaseClient
    .from("perfiles_app")
    .select("id,nombre,usuario,rol,activo,miembro_id")
    .eq("id", session.user.id)
    .maybeSingle();
  if (error || !profile || profile.rol !== "hermano") return renacerBaseLoadData();

  if (!profile.activo || !profile.miembro_id) {
    await window.supabaseClient.auth.signOut();
    currentUser = null;
    stopRealtimeSync();
    showLoginView();
    showAccessOption("member-login");
    setPortalMessage("member-login-message", "Tu acceso está pendiente de aprobación o aún no está vinculado a un perfil congregacional. Contacta a un administrador.");
    return;
  }

  currentUser = {
    id: profile.id,
    name: profile.nombre,
    username: profile.usuario || session.user.email,
    email: session.user.email,
    role: "hermano",
    miembroId: profile.miembro_id
  };
  stopRealtimeSync();
  await loadMemberPortalData();
  document.getElementById("login-view").classList.add("hidden");
  document.getElementById("app-container").classList.add("hidden");
  document.getElementById("member-portal-container").classList.remove("hidden");
  document.getElementById("member-portal-user-name").textContent = profile.nombre || session.user.email;
  startMemberPortalRealtime();
  if (window.lucide) lucide.createIcons();
};

function stopMemberPortalRealtime() {
  if (memberPortalChannel) {
    window.supabaseClient.removeChannel(memberPortalChannel);
    memberPortalChannel = null;
  }
}

function startMemberPortalRealtime() {
  stopMemberPortalRealtime();
  memberPortalChannel = window.supabaseClient.channel("renacer-portal-hermanos")
    .on("postgres_changes", { event: "*", schema: "public", table: "peticiones_oracion" }, loadMemberPortalData)
    .on("postgres_changes", { event: "*", schema: "public", table: "avisos_congregacion" }, loadMemberPortalData)
    .on("postgres_changes", { event: "*", schema: "public", table: "miembros_app" }, loadMemberPortalData)
    .subscribe();
}

async function loadMemberPortalData() {
  if (!currentUser || currentUser.role !== "hermano") return;
  const memberId = currentUser.miembroId;
  try {
    const results = await Promise.all([
      window.supabaseClient.from("miembros_app")
        .select("id,name,phone,email,address,marital_status,spouse_name,ministry,baptized,birthday")
        .eq("id", memberId).single(),
      window.supabaseClient.from("peticiones_oracion")
        .select("id,description,created_at").eq("member_id", memberId).order("created_at", { ascending: false }),
      window.supabaseClient.from("avisos_congregacion")
        .select("id,title,body,published_at,created_at").eq("published", true).order("published_at", { ascending: false }),
      window.supabaseClient.rpc("listar_cumpleanos_congregacion")
    ]);
    results.forEach(result => { if (result.error) throw result.error; });
    memberPortalProfile = results[0].data;
    memberPortalPrayerRows = results[1].data || [];
    memberPortalAnnouncementRows = results[2].data || [];
    memberPortalBirthdayRows = results[3].data || [];
    renderMemberPortal();
  } catch (error) {
    console.error("Error cargando el portal:", error);
    const status = document.getElementById("member-portal-announcements");
    if (status) status.textContent = "No se pudo actualizar el portal. Comprueba la conexión o vuelve a intentarlo.";
  }
}

function portalSetText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value || "No registrado";
}

function portalFormatDate(value, includeYear=true) {
  if (!value) return "—";
  const parts = String(value).slice(0, 10).split("-");
  if (parts.length !== 3) return value;
  return includeYear ? parts[2] + "/" + parts[1] + "/" + parts[0] : parts[2] + "/" + parts[1];
}

function renderMemberPortal() {
  const m = memberPortalProfile;
  if (!m) return;
  portalSetText("member-profile-name", m.name);
  portalSetText("member-profile-phone", m.phone);
  portalSetText("member-profile-email", m.email);
  portalSetText("member-profile-marital", m.marital_status);
  portalSetText("member-profile-spouse", m.spouse_name);
  portalSetText("member-profile-ministry", m.ministry || "General");
  portalSetText("member-profile-baptized", m.baptized);
  portalSetText("member-profile-birthday", portalFormatDate(m.birthday));
  portalSetText("member-profile-address", m.address);
  portalSetText("member-portal-welcome", "Hola, " + m.name);

  const prayers = document.getElementById("member-portal-prayers");
  prayers.innerHTML = "";
  if (!memberPortalPrayerRows.length) prayers.textContent = "Todavía no has enviado peticiones de oración.";
  memberPortalPrayerRows.forEach(row => {
    const card = document.createElement("div");
    card.className = "rounded-lg bg-slate-50 dark:bg-slate-900 p-3 border border-slate-100 dark:border-slate-700";
    const date = document.createElement("p");
    date.className = "text-[10px] text-slate-400 mb-1";
    date.textContent = row.created_at ? new Date(row.created_at).toLocaleString("es-CL") : "";
    const body = document.createElement("p");
    body.className = "text-sm whitespace-pre-wrap";
    body.textContent = row.description;
    card.append(date, body);
    prayers.appendChild(card);
  });

  const announcements = document.getElementById("member-portal-announcements");
  announcements.innerHTML = "";
  if (!memberPortalAnnouncementRows.length) announcements.textContent = "Por el momento no hay avisos publicados.";
  memberPortalAnnouncementRows.forEach(row => {
    const card = document.createElement("article");
    card.className = "rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50/60 dark:bg-amber-900/10 p-4";
    const title = document.createElement("h4");
    title.className = "font-bold";
    title.textContent = row.title;
    const date = document.createElement("p");
    date.className = "text-[10px] text-amber-700 dark:text-amber-400 mt-1";
    date.textContent = row.published_at ? new Date(row.published_at).toLocaleDateString("es-CL") : "";
    const body = document.createElement("p");
    body.className = "text-sm whitespace-pre-wrap mt-2";
    body.textContent = row.body;
    card.append(title, date, body);
    announcements.appendChild(card);
  });

  const birthdays = document.getElementById("member-portal-birthdays");
  birthdays.innerHTML = "";
  if (!memberPortalBirthdayRows.length) birthdays.textContent = "No hay cumpleaños registrados.";
  memberPortalBirthdayRows.forEach(row => {
    const item = document.createElement("div");
    item.className = "flex items-center justify-between gap-3 rounded-lg bg-slate-50 dark:bg-slate-900 p-3 border border-slate-100 dark:border-slate-700";
    const name = document.createElement("span");
    name.className = "text-sm font-medium";
    name.textContent = row.nombre;
    const date = document.createElement("span");
    date.className = "text-xs font-semibold text-amber-600 dark:text-amber-400";
    date.textContent = portalFormatDate(row.cumpleanos, false);
    item.append(name, date);
    birthdays.appendChild(item);
  });
}

async function submitMemberPrayerRequest(event) {
  event.preventDefault();
  if (!currentUser || currentUser.role !== "hermano") return;
  const description = document.getElementById("member-prayer-description").value.trim();
  if (!description) return;
  const button = event.submitter || event.target.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const { error } = await window.supabaseClient.from("peticiones_oracion").insert({
      id: "portal_" + crypto.randomUUID(),
      member_id: currentUser.miembroId,
      description,
      created_at: new Date().toISOString(),
      created_by: currentUser.id
    });
    if (error) throw error;
    document.getElementById("member-prayer-form").reset();
    setPortalMessage("member-prayer-message", "Tu petición fue registrada correctamente.", true);
    await loadMemberPortalData();
  } catch (error) {
    console.error("Error guardando petición:", error);
    setPortalMessage("member-prayer-message", "No se pudo guardar la petición. " + error.message);
  } finally {
    if (button) button.disabled = false;
  }
}

/* ADMINISTRACIÓN DE AVISOS */
async function openAnnouncementsModal() {
  if (!currentUser || currentUser.role !== "admin") return;
  document.getElementById("announcements-modal").classList.remove("hidden");
  resetAnnouncementForm();
  await loadAnnouncementsAdmin();
}

function closeAnnouncementsModal() {
  document.getElementById("announcements-modal").classList.add("hidden");
}

function resetAnnouncementForm() {
  const form = document.getElementById("announcement-form");
  if (form) form.reset();
  document.getElementById("announcement-id").value = "";
  document.getElementById("announcement-published").checked = true;
  document.getElementById("announcement-form-title").textContent = "Nuevo aviso";
  document.getElementById("announcement-admin-message").classList.add("hidden");
}

function setAnnouncementAdminMessage(message, isError=false) {
  const el = document.getElementById("announcement-admin-message");
  el.textContent = message;
  el.className = "text-xs " + (isError ? "text-rose-600" : "text-emerald-600");
}

async function loadAnnouncementsAdmin() {
  if (!currentUser || currentUser.role !== "admin") return;
  const status = document.getElementById("announcement-admin-status");
  const list = document.getElementById("announcement-admin-list");
  status.textContent = "Cargando avisos...";
  list.innerHTML = "";
  try {
    const { data, error } = await window.supabaseClient.from("avisos_congregacion")
      .select("id,title,body,published,published_at,created_at")
      .order("created_at", { ascending: false });
    if (error) throw error;
    renacerAnnouncementRows = data || [];
    if (!renacerAnnouncementRows.length) {
      status.textContent = "Todavía no hay avisos.";
      return;
    }
    status.textContent = "Avisos registrados: " + renacerAnnouncementRows.length;
    renacerAnnouncementRows.forEach(row => {
      const card = document.createElement("div");
      card.className = "border border-slate-200 dark:border-slate-700 rounded-xl p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3";
      const info = document.createElement("div");
      info.className = "min-w-0";
      const title = document.createElement("p");
      title.className = "font-semibold text-sm";
      title.textContent = row.title;
      const body = document.createElement("p");
      body.className = "text-xs text-slate-500 mt-1 whitespace-pre-wrap";
      body.textContent = row.body;
      const state = document.createElement("p");
      state.className = "text-[10px] mt-1 " + (row.published ? "text-emerald-600" : "text-amber-600");
      state.textContent = row.published ? "Publicado" : "Borrador";
      info.append(title, body, state);
      const actions = document.createElement("div");
      actions.className = "flex flex-wrap gap-1.5 shrink-0";
      const edit = document.createElement("button");
      edit.className = "px-2.5 py-1.5 rounded-md border text-xs";
      edit.textContent = "Editar";
      edit.onclick = () => editAnnouncement(row.id);
      const toggle = document.createElement("button");
      toggle.className = "px-2.5 py-1.5 rounded-md bg-amber-500 text-church-900 text-xs font-semibold";
      toggle.textContent = row.published ? "Retirar" : "Publicar";
      toggle.onclick = () => toggleAnnouncementPublished(row.id, !row.published);
      const remove = document.createElement("button");
      remove.className = "px-2.5 py-1.5 rounded-md bg-rose-600 text-white text-xs";
      remove.textContent = "Eliminar";
      remove.onclick = () => deleteAnnouncement(row.id);
      actions.append(edit, toggle, remove);
      card.append(info, actions);
      list.appendChild(card);
    });
  } catch (error) {
    console.error("Error cargando avisos:", error);
    status.textContent = "No se pudieron cargar los avisos: " + error.message;
  }
}

async function saveAnnouncement(event) {
  event.preventDefault();
  if (!currentUser || currentUser.role !== "admin") return;
  const id = document.getElementById("announcement-id").value;
  const title = document.getElementById("announcement-title").value.trim();
  const body = document.getElementById("announcement-body").value.trim();
  const published = document.getElementById("announcement-published").checked;
  if (!title || !body) return;
  const button = event.submitter || event.target.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const payload = {
      title, body, published,
      published_at: published ? new Date().toISOString() : null,
      updated_at: new Date().toISOString()
    };
    const query = id
      ? window.supabaseClient.from("avisos_congregacion").update(payload).eq("id", id)
      : window.supabaseClient.from("avisos_congregacion").insert({ ...payload, created_by: currentUser.id });
    const { error } = await query;
    if (error) throw error;
    resetAnnouncementForm();
    setAnnouncementAdminMessage("Aviso guardado correctamente.");
    await loadAnnouncementsAdmin();
  } catch (error) {
    console.error("Error guardando aviso:", error);
    setAnnouncementAdminMessage("No se pudo guardar el aviso: " + error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}

function editAnnouncement(id) {
  const row = renacerAnnouncementRows.find(item => item.id === id);
  if (!row) return;
  document.getElementById("announcement-id").value = row.id;
  document.getElementById("announcement-title").value = row.title;
  document.getElementById("announcement-body").value = row.body;
  document.getElementById("announcement-published").checked = !!row.published;
  document.getElementById("announcement-form-title").textContent = "Editar aviso";
  document.getElementById("announcement-title").focus();
}

async function toggleAnnouncementPublished(id, published) {
  if (!currentUser || currentUser.role !== "admin") return;
  const { error } = await window.supabaseClient.from("avisos_congregacion")
    .update({ published, published_at: published ? new Date().toISOString() : null, updated_at: new Date().toISOString() })
    .eq("id", id);
  if (error) { alert("No se pudo actualizar el aviso: " + error.message); return; }
  await loadAnnouncementsAdmin();
}

async function deleteAnnouncement(id) {
  if (!currentUser || currentUser.role !== "admin") return;
  if (!confirm("¿Eliminar definitivamente este aviso?")) return;
  const { error } = await window.supabaseClient.from("avisos_congregacion").delete().eq("id", id);
  if (error) { alert("No se pudo eliminar el aviso: " + error.message); return; }
  await loadAnnouncementsAdmin();
}

const renacerOriginalLogout = handleLogout;
handleLogout = async function() {
  stopMemberPortalRealtime();
  await renacerOriginalLogout();
  const portal = document.getElementById("member-portal-container");
  if (portal) portal.classList.add("hidden");
};

/* Mostrar la administración de avisos únicamente a administradores. */
const renacerBaseApplyRolePermissions = applyRolePermissions;
applyRolePermissions = function() { renacerBaseApplyRolePermissions(); const button = document.getElementById('btn-manage-announcements'); if (button) button.classList.toggle('hidden', !currentUser || currentUser.role !== 'admin'); };
