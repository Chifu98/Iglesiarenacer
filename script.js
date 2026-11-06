// SECURITY UTILITY: DOM XSS Mitigation (CWE-79 / CAPEC-63)
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

let users = [];
let currentUser = null;

let rolePreviewOriginalUser = null;
let rolePreviewActive = false;
const rolePreviewMinistries = ["General", "Alabanza", "Servidor", "Niños", "Jóvenes", "Oración", "Evangelismo", "Redes", "Damas", "Matrimonio", "Hombres"];

function startRolePreview(role, selectedMinistry = "") {
  const adminUser = rolePreviewOriginalUser || currentUser;
  if (!adminUser || !adminUser.roles?.includes("admin")) return;
  const supported = ["admin", "pastor", "lider", "miembro"];
  if (!supported.includes(role)) return;
  if (!rolePreviewOriginalUser) rolePreviewOriginalUser = { ...currentUser, roles: [...currentUser.roles] };

  const originalMinistry = rolePreviewOriginalUser.ministry || "General";
  const ministry = role === "pastor" ? "General" :
    (role === "lider" || role === "miembro"
      ? (rolePreviewMinistries.includes(selectedMinistry) ? selectedMinistry :
        (rolePreviewMinistries.includes(originalMinistry) ? originalMinistry : "General"))
      : originalMinistry);
  // Se conserva la identidad y la ficha real del administrador; solo se simulan rol y ministerio en memoria.
  const previewUser = {
    ...rolePreviewOriginalUser,
    roles: [role],
    role,
    memberId: rolePreviewOriginalUser.memberId || "",
    ministry: role === "pastor" ? "General" : ministry
  };
  currentUser = previewUser;
  rolePreviewActive = role !== "admin";
  const bar = document.getElementById("role-preview-bar");
  if (bar) {
    bar.classList.toggle("hidden", !rolePreviewActive);
    const label = document.getElementById("role-preview-label");
    if (label) label.textContent = roleDisplayName(role) + ((role === "lider" || role === "miembro") ? " · " + ministry : "");
  }
  const ministryControl = document.getElementById("role-preview-ministry-control");
  const ministrySelect = document.getElementById("role-preview-ministry-select");
  const canChooseMinistry = role === "lider" || role === "miembro";
  if (ministryControl) ministryControl.classList.toggle("hidden", !rolePreviewActive || !canChooseMinistry);
  if (ministrySelect && canChooseMinistry) ministrySelect.value = ministry;
  const selector = document.getElementById("role-preview-select");
  if (selector) selector.value = role;
  const app = document.getElementById("app-container");
  if (app) app.classList.toggle("role-preview-mode", rolePreviewActive);
  showAppView();
}

function changeRolePreviewMinistry(ministry) {
  if (!rolePreviewActive || !rolePreviewOriginalUser || !["lider", "miembro"].includes(currentUser?.role)) return;
  startRolePreview(currentUser.role, ministry);
}

function stopRolePreview() {
  if (!rolePreviewOriginalUser) return;
  currentUser = rolePreviewOriginalUser;
  rolePreviewOriginalUser = null;
  rolePreviewActive = false;
  const bar = document.getElementById("role-preview-bar");
  if (bar) bar.classList.add("hidden");
  const ministryControl = document.getElementById("role-preview-ministry-control");
  if (ministryControl) ministryControl.classList.add("hidden");
  const app = document.getElementById("app-container");
  if (app) app.classList.remove("role-preview-mode");
  const selector = document.getElementById("role-preview-select");
  if (selector) selector.value = "admin";
  showAppView();
}

document.addEventListener("click", event => {
  if (!rolePreviewActive) return;
  const target = event.target.closest("button, input[type='submit']");
  if (!target) return;
  if (target.closest("#role-preview-bar")) return;
  const action = target.getAttribute("onclick") || "";
  if (/showTab|switchTab|showSection|navigateTo|setActiveTab|changeTab/i.test(action)) return;
  event.preventDefault();
  event.stopImmediatePropagation();
  alert("La vista por roles es solo de consulta. Sal de la vista previa para realizar acciones.");
}, true);

document.addEventListener("submit", event => {
  if (!rolePreviewActive) return;
  event.preventDefault();
  event.stopImmediatePropagation();
  alert("La vista por roles es solo de consulta. Sal de la vista previa para realizar acciones.");
}, true);

function hasRole(role) {
  return !!(currentUser && Array.isArray(currentUser.roles) && currentUser.roles.includes(role));
}
function roleDisplayName(role) {
  return ({ hermano: "Miembro", miembro: "Miembro", admin: "Administrador", pastor: "Pastor", lider: "Líder" })[role] || role;
}
function hasServerMinistryPermissions() {
  return !!(currentUser && currentUser.ministry === "Servidor");
}
function isMemberOnly() {
  return !!(currentUser && (hasRole("miembro") || hasRole("hermano")) && !hasRole("admin") && !hasRole("pastor") &&
    !hasRole("lider") && !hasServerMinistryPermissions());
}
let members = [];
let visitCards = [];
let prayerRequests = [];
let announcements = [];
let currentAvatarBase64 = "";
let memberBirthdayData = null;
let antecedentNotes = [];

let realtimeChannel = null;
let realtimeRefreshTimer = null;

function getProfilePhotoPath(value) {
  if (typeof value !== "string" || !value) return null;
  const marker = "storage:profile-photos/";
  if (value.startsWith(marker)) return value.slice(marker.length);
  try {
    const url = new URL(value);
    const match = url.pathname.match(/\/storage\/v1\/object\/(?:public|sign)\/profile-photos\/(.+)$/);
    return match ? decodeURIComponent(match[1]) : null;
  } catch (_) {
    return null;
  }
}

function normalizeProfileAvatarForDb(value) {
  const path = getProfilePhotoPath(value);
  return path ? "storage:profile-photos/" + path : (value || null);
}

async function resolveProfileAvatarForDisplay(value) {
  const path = getProfilePhotoPath(value);
  if (!path) return value || "";
  const { data, error } = await window.supabaseClient.storage
    .from("profile-photos")
    .createSignedUrl(path, 86400);
  if (error || !data?.signedUrl) {
    console.warn("No se pudo generar un enlace temporal para una fotografía de perfil:", error);
    return "";
  }
  return data.signedUrl;
}

function mapDbMemberToApp(row) {
  return {
    id: row.id,
    name: row.name || "",
    phone: row.phone || "",
    email: row.email || "",
    address: row.address || "",
    maritalStatus: row.marital_status || "Soltero (a)",
    spouseType: row.spouse_type || "none",
    spouseName: row.spouse_name || "",
    spouseId: row.spouse_id || "",
    ministry: row.ministry || "General",
    status: row.status || "Activo",
    baptized: row.baptized || "No",
    birthday: row.birthday || "",
    notes: "", // Notas pastorales privadas, cargadas según RLS.
    leaderNotes: "",
    avatar: row.avatar || "",
    inviterMemberId: row.inviter_member_id || "",
    inviterName: row.inviter_name || "",
    inviterRelationship: row.inviter_relationship || "",
    createdAt: row.created_at || ""
  };
}

function mapAppMemberToDb(member) {
  return {
    id: String(member.id),
    name: member.name,
    phone: member.phone || null,
    email: member.email || null,
    address: member.address || null,
    marital_status: member.maritalStatus || null,
    spouse_type: member.spouseType || null,
    spouse_name: member.spouseName || null,
    spouse_id: member.spouseId || null,
    ministry: member.ministry || "General",
    status: member.status || "Activo",
    baptized: member.baptized || null,
    birthday: member.birthday || null,
    avatar: normalizeProfileAvatarForDb(member.avatar),
    inviter_member_id: member.status !== "Activo" ? (member.inviterMemberId || null) : null,
    inviter_name: member.status !== "Activo" ? (member.inviterName || null) : null,
    inviter_relationship: member.status !== "Activo" ? (member.inviterRelationship || null) : null,
    created_at: member.createdAt || new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
}

function mapDbRequestToApp(row) {
  return {
    id: row.id,
    memberId: row.member_id || "",
    memberName: row.member_name || "",
    text: row.description || "",
    createdAt: row.created_at,
    createdBy: row.created_by || ""
  };
}

function mapAppRequestToDb(request) {
  return {
    id: String(request.id),
    member_id: request.memberId || null,
    description: request.text,
    created_at: request.createdAt || new Date().toISOString()
  };
}

async function refreshCloudData() {
  const client = window.supabaseClient;
  const [membersResult, requestsResult, announcementsResult] = await Promise.all([
    client.from("miembros_app").select("*").order("created_at", { ascending: false }),
    client.from("peticiones_oracion").select("*").order("created_at", { ascending: false }),
    client.from("anuncios").select("*").order("creado_en", { ascending: false })
  ]);

  if (membersResult.error) throw membersResult.error;
  if (requestsResult.error) throw requestsResult.error;
  if (announcementsResult.error) throw announcementsResult.error;

  if (currentUser && !rolePreviewActive) {
    if (currentUser.memberId) {
      const ownMemberRow = (membersResult.data || []).find(row => String(row.id) === String(currentUser.memberId));
      currentUser.ministry = ownMemberRow ? (ownMemberRow.ministry || "General") : "General";
    } else {
      currentUser.ministry = "General";
    }
  }

  memberBirthdayData = null;
  if (isMemberOnly()) {
    const { data: birthdayRows, error: birthdayError } = await client.rpc("listar_cumpleanos_congregacion");
    if (birthdayError) {
      console.warn("No se pudo cargar el listado de cumpleaños autorizado:", birthdayError);
      memberBirthdayData = [];
    } else {
      memberBirthdayData = (birthdayRows || []).map(row => ({
        name: row.nombre || "",
        birthday: row.cumpleanos || "",
        avatar: "",
        phone: ""
      }));
    }
  }

  let privateNotes = new Map();
  let leaderNotes = new Map();
  if (currentUser && (hasRole("admin") || hasRole("pastor"))) {
    const notesResult = await client.from("notas_pastorales").select("miembro_id,nota");
    if (notesResult.error) throw notesResult.error;
    privateNotes = new Map((notesResult.data || []).map(row => [row.miembro_id, row.nota || ""]));
  }
  if (currentUser && (hasRole("admin") || hasRole("pastor") || hasRole("lider"))) {
    const notesResult = await client.from("notas_lideres").select("miembro_id,lider_id,nota");
    if (notesResult.error) throw notesResult.error;
    (notesResult.data || []).forEach(row => {
      const current = leaderNotes.get(row.miembro_id) || [];
      const owner = row.lider_id ? row.lider_id.slice(0, 8) : "histórica";
      if (row.nota) current.push("Líder " + owner + ": " + row.nota);
      leaderNotes.set(row.miembro_id, current);
    });
  }

  members = await Promise.all((membersResult.data || []).map(async row => {
    const member = {
      ...mapDbMemberToApp(row),
      notes: privateNotes.get(row.id) || "",
      leaderNotes: (leaderNotes.get(row.id) || []).join("\n\n")
    };
    member.avatar = await resolveProfileAvatarForDisplay(member.avatar);
    return member;
  }));
  const antecedentResult = await client.from("notas_antecedentes")
    .select("id,miembro_id,tipo,contenido,autor_id,autor_nombre,created_at")
    .order("created_at", { ascending: false });
  if (antecedentResult.error) throw antecedentResult.error;
  antecedentNotes = antecedentResult.data || [];
  const visitCardsViaRpc = !!currentUser && !hasRole("admin") && !hasRole("pastor") &&
    (hasRole("lider") || hasRole("miembro") || hasRole("hermano") || hasServerMinistryPermissions());
  if (visitCardsViaRpc) {
    // La RPC entrega exclusivamente los datos de las tarjetas; no habilita lectura de fichas generales.
    const { data: visitRows, error: visitError } = await client.rpc("listar_tarjetas_visita_servidor");
    if (visitError) throw visitError;
    visitCards = (visitRows || []).map(row => ({
      id: row.id,
      name: row.name || "",
      status: row.status || "En Visita",
      createdAt: row.created_at || "",
      inviterName: row.inviter_name || "",
      inviterRelationship: row.inviter_relationship || ""
    }));
  } else {
    visitCards = members.filter(member => member.status === "En Visita");
  }
  prayerRequests = (requestsResult.data || []).map(mapDbRequestToApp);
  announcements = announcementsResult.data || [];
}

async function saveMembers() {
  if (!members.length) return;
  const rows = members.map(mapAppMemberToDb);
  const { error } = await window.supabaseClient
    .from("miembros_app")
    .upsert(rows, { onConflict: "id" });

  if (error) throw error;

  // Las notas pastorales solo pueden ser gestionadas por Admin y Pastor.
  if (currentUser && (hasRole("admin") || hasRole("pastor"))) {
    const privateRows = members.map(member => ({
      miembro_id: String(member.id), nota: member.notes || "",
      updated_at: new Date().toISOString(), updated_by: currentUser.id
    }));
    if (privateRows.length) {
      const { error: notesError } = await window.supabaseClient.from("notas_pastorales")
        .upsert(privateRows, { onConflict: "miembro_id" });
      if (notesError) throw notesError;
    }
  }
  // Las notas de líderes se guardan por separado por miembro y líder; el guardado masivo no sobrescribe notas ajenas.
}

async function saveRequests() {
  if (!prayerRequests.length) return;
  const rows = prayerRequests.map(mapAppRequestToDb);
  const { error } = await window.supabaseClient
    .from("peticiones_oracion")
    .upsert(rows, { onConflict: "id" });

  if (error) throw error;
}

async function loadProfilesFromCloud() {
  if (!currentUser) return;

  if (!hasRole("admin")) {
    users = [currentUser];
    return;
  }

  let { data, error } = await window.supabaseClient
    .from("perfiles_app")
    .select("id,nombre,usuario,rol,roles,activo,estado_solicitud,miembro_id")
    .order("nombre", { ascending: true });

  // Compatibilidad temporal mientras el administrador ejecuta la migración SQL.
  if (error && error.code === "42703") {
    ({ data, error } = await window.supabaseClient
      .from("perfiles_app")
      .select("id,nombre,usuario,rol,activo,estado_solicitud,miembro_id")
      .order("nombre", { ascending: true }));
  }
  if (error) throw error;

  users = (data || []).map(profile => ({
    id: profile.id,
    name: profile.nombre,
    username: profile.usuario || profile.id,
    roles: (Array.isArray(profile.roles) ? profile.roles : (profile.rol ? [profile.rol] : [])),
    role: profile.rol,
    active: profile.activo,
    requestStatus: profile.estado_solicitud || (profile.activo ? "aprobado" : "pendiente"),
    memberId: profile.miembro_id || ""
  }));
}

async function loadData() {
  const monthField = document.getElementById("share-birthday-month");
  if (monthField) {
    monthField.value = String(new Date().getMonth() + 1).padStart(2, "0");
  }

  try {
    const { data, error } = await window.supabaseClient.auth.getSession();
    if (error) throw error;

    const session = data.session;
    if (!session) {
      currentUser = null;
      stopRealtimeSync();
      showLoginView();
      return;
    }

    let { data: profile, error: profileError } = await window.supabaseClient
      .from("perfiles_app")
      .select("id,nombre,usuario,rol,roles,activo,miembro_id")
      .eq("id", session.user.id)
      .maybeSingle();

    // Compatibilidad temporal mientras el administrador ejecuta la migración SQL.
    if (profileError && profileError.code === "42703") {
      ({ data: profile, error: profileError } = await window.supabaseClient
        .from("perfiles_app")
        .select("id,nombre,usuario,rol,activo,miembro_id")
        .eq("id", session.user.id)
        .maybeSingle());
    }
    if (profileError) throw profileError;

    if (!profile || !profile.activo) {
      await window.supabaseClient.auth.signOut();
      currentUser = null;
      showLoginView();
      showAccessOption("login");
      const errorDiv = document.getElementById("login-error");
      errorDiv.textContent = "Tu cuenta está pendiente de aprobación o se encuentra inactiva. Contacta al administrador.";
      errorDiv.classList.remove("hidden");
      return;
    }

    currentUser = {
      id: profile.id,
      name: profile.nombre,
      username: profile.usuario || session.user.email,
      email: session.user.email,
      roles: (Array.isArray(profile.roles) ? profile.roles : (profile.rol ? [profile.rol] : [])),
    role: profile.rol,
      memberId: profile.miembro_id || ""
    };

    await refreshCloudData();
    await loadProfilesFromCloud();
    showAppView();
    startRealtimeSync();
  } catch (error) {
    console.error("Error cargando datos de Supabase:", error);
    currentUser = null;
    stopRealtimeSync();
    showLoginView();
    showAccessOption("login");
    const errorDiv = document.getElementById("login-error");
    errorDiv.textContent = "No se pudo cargar tu perfil o los datos. Revisa tu conexión y los permisos de Supabase.";
    errorDiv.classList.remove("hidden");
  }
}

function showAccessOption(option) {
  const menu = document.getElementById("access-menu");
  const loginPanel = document.getElementById("login-panel");
  const membersPanel = document.getElementById("public-member-panel");
  const loginError = document.getElementById("login-error");
  if (menu) menu.classList.toggle("hidden", option !== "menu");
  if (loginPanel) loginPanel.classList.toggle("hidden", option !== "login");
  if (membersPanel) membersPanel.classList.toggle("hidden", option !== "members");
  if (loginError) loginError.classList.add("hidden");
  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

function togglePublicSpouseField() {
  const marital = document.getElementById("public-member-marital");
  const spouse = document.getElementById("public-spouse-field");
  if (!marital || !spouse) return;
  const show = marital.value === "Casado (a)" || marital.value === "Novio (a)";
  spouse.classList.toggle("hidden", !show);
}

function showPublicMemberMessage(message, success = false) {
  const box = document.getElementById("public-member-message");
  box.textContent = message;
  box.className = "p-3 rounded-xl text-xs " + (success
    ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-300"
    : "bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300");
  box.classList.remove("hidden");
}

async function submitPublicMemberRegistration(event) {
  event.preventDefault();
  const form = document.getElementById("public-member-form");
  const button = document.getElementById("public-member-submit");
  if (document.getElementById("public-member-website").value.trim()) return;

  const name = document.getElementById("public-member-name").value.trim();
  const phone = document.getElementById("public-member-phone").value.trim();
  const email = document.getElementById("public-member-email").value.trim().toLowerCase();
  const password = document.getElementById("public-member-password").value;
  const passwordConfirm = document.getElementById("public-member-password-confirm").value;
  const address = document.getElementById("public-member-address").value.trim();
  const maritalStatus = document.getElementById("public-member-marital").value;
  const spouseName = (maritalStatus === "Casado (a)" || maritalStatus === "Novio (a)")
    ? document.getElementById("public-member-spouse").value.trim() : "";
  const ministry = "General";
  const baptized = document.getElementById("public-member-baptized").value;
  const birthday = document.getElementById("public-member-birthday").value;

  if (name.length < 3 || phone.length < 7 || !email || !birthday || password.length < 8 || passwordConfirm.length < 8) {
    showPublicMemberMessage("Revisa tus datos. El correo es obligatorio y ambas contraseñas deben tener al menos 8 caracteres.");
    return;
  }
  if (password !== passwordConfirm) {
    showPublicMemberMessage("Las contraseñas no coinciden. Verifica ambos campos antes de continuar.");
    document.getElementById("public-member-password-confirm").focus();
    return;
  }

  button.disabled = true;
  button.textContent = "Creando cuenta y solicitud...";
  let requestId = null;
  try {
    const { data: request, error: requestError } = await window.supabaseClient.rpc(
      "crear_solicitud_registro_miembro",
      {
        p_name: name,
        p_phone: phone,
        p_email: email,
        p_address: address || null,
        p_marital_status: maritalStatus,
        p_spouse_type: spouseName ? "text" : "none",
        p_spouse_name: spouseName || null,
        p_ministry: ministry,
        p_baptized: baptized,
        p_birthday: birthday
      }
    );
    if (requestError) throw requestError;
    requestId = request;
    if (!requestId) throw new Error("No se pudo obtener el identificador de la solicitud.");
    const { data, error } = await window.supabaseClient.auth.signUp({
      email,
      password,
      options: {
        data: { nombre: name, tipo_cuenta: "miembro", solicitud_id: requestId },
        emailRedirectTo: window.location.origin
      }
    });
    if (error) throw error;
    if (!data.user) throw new Error("Supabase no devolvió la cuenta creada. Contacta al administrador.");

    // La confirmación de correo debe estar desactivada en Supabase Auth para que
    // las nuevas cuentas queden creadas sin verificación por email.
    if (Array.isArray(data.user.identities) && data.user.identities.length === 0) {
      throw new Error("Este correo ya tiene una cuenta o no está disponible. Si ya te registraste, inicia sesión o contacta al administrador.");
    }

    if (data.session) await window.supabaseClient.auth.signOut();

    form.reset();
    togglePublicSpouseField();
    showPublicMemberMessage(
      "¡Solicitud enviada correctamente! No necesitas confirmar tu correo. Tu cuenta quedará pendiente y solo podrás ingresar cuando un administrador apruebe tu incorporación.",
      true
    );
  } catch (error) {
    console.error("Error creando solicitud/cuenta de miembro:", { error, requestId });
    showPublicMemberMessage(
      "No se pudo completar el registro. " +
      (requestId
        ? "Si la solicitud quedó guardada, el administrador podrá revisarla. No vuelvas a enviarla hasta confirmar su estado. "
        : "") +
      (error.message || "Inténtalo nuevamente.")
    );
  } finally {
    button.disabled = false;
    button.textContent = "Enviar solicitud de registro";
  }
}


async function handleLogin(event) {
  event.preventDefault();

  const email = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const errorDiv = document.getElementById("login-error");
  errorDiv.classList.add("hidden");

  const button = event.submitter || event.target.querySelector('button[type="submit"]');
  if (button) button.disabled = true;

  try {
    const { error } = await window.supabaseClient.auth.signInWithPassword({
      email: email,
      password: password
    });

    if (error) throw error;
    await loadData();
  } catch (error) {
    console.error("Error de inicio de sesión:", error);
    errorDiv.textContent = "Correo o contraseña incorrectos, o cuenta sin acceso.";
    errorDiv.classList.remove("hidden");
  } finally {
    if (button) button.disabled = false;
  }
}

async function handlePasswordReset() {
  const email = document.getElementById("login-username").value.trim();
  if (!email) {
    alert("Escribe primero tu correo electrónico en el campo de acceso.");
    return;
  }

  const { error } = await window.supabaseClient.auth.resetPasswordForEmail(email, {
    redirectTo: new URL("restablecer.html", window.location.href).toString()
  });

  if (error) {
    alert("No se pudo enviar el correo: " + error.message);
    return;
  }

  alert("Te enviamos un enlace de recuperación. Revisa tu correo electrónico.");
}

async function handleLogout() {
  stopRealtimeSync();
  await window.supabaseClient.auth.signOut();
  currentUser = null;
  users = [];
  members = [];
  prayerRequests = [];
  announcements = [];
  showLoginView();
}

function showLoginView() {
  document.getElementById("login-view").classList.remove("hidden");
  document.getElementById("app-container").classList.add("hidden");
  showAccessOption("menu");
}


/* NOTIFICACIONES WEB PUSH: solo anuncios congregacionales */
const RENACER_VAPID_PUBLIC_KEY = "BN0YsXxJFvWv9JAPkOIsnhTQwveq4IP3kFKqRwd7-O9tPc1opLTIXqF9-3yC3LDnY3jP8RW7QJ-GZJtfVplexUY";

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  return Uint8Array.from([...raw].map(char => char.charCodeAt(0)));
}

function updateAnnouncementPushButton(enabled) {
  const button = document.getElementById("btn-announcement-notifications");
  if (!button) return;
  button.dataset.enabled = enabled ? "true" : "false";
  button.title = enabled ? "Desactivar avisos de anuncios" : "Activar avisos de anuncios";
  button.setAttribute("aria-label", button.title);
  button.innerHTML = (enabled
    ? '<i data-lucide="bell-ring" class="w-5 h-5"></i><span class="hidden sm:inline">Avisos activos</span>'
    : '<i data-lucide="bell" class="w-5 h-5"></i><span class="hidden sm:inline">Activar avisos</span>');
  if (window.lucide) if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

async function refreshAnnouncementPushButton() {
  const button = document.getElementById("btn-announcement-notifications");
  if (!button) return;
  if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    button.classList.add("hidden");
    return;
  }
  try {
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription();
    updateAnnouncementPushButton(!!subscription);
  } catch (error) {
    console.warn("No se pudo consultar el estado de avisos:", error);
    updateAnnouncementPushButton(false);
  }
}

async function toggleAnnouncementNotifications() {
  if (!currentUser) return;
  if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    alert("Este navegador no admite notificaciones push. En iPhone, instala Renacer en la pantalla de inicio y utiliza iOS 16.4 o posterior.");
    return;
  }

  const button = document.getElementById("btn-announcement-notifications");
  if (button) button.disabled = true;
  try {
    const registration = await navigator.serviceWorker.ready;
    let subscription = await registration.pushManager.getSubscription();

    if (subscription) {
      const endpoint = subscription.endpoint;
      await subscription.unsubscribe();
      const { error } = await window.supabaseClient
        .from("suscripciones_push").delete().eq("endpoint", endpoint);
      if (error) throw error;
      updateAnnouncementPushButton(false);
      alert("Avisos de anuncios desactivados en este dispositivo.");
      return;
    }

    const permission = Notification.permission === "default"
      ? await Notification.requestPermission()
      : Notification.permission;
    if (permission !== "granted") {
      alert("No se concedió permiso para notificaciones. Puedes habilitarlo desde la configuración del navegador.");
      return;
    }

    subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(RENACER_VAPID_PUBLIC_KEY)
    });
    const json = subscription.toJSON();
    const { error } = await window.supabaseClient.from("suscripciones_push").upsert({
      usuario_id: currentUser.id,
      endpoint: subscription.endpoint,
      p256dh: json.keys?.p256dh,
      auth: json.keys?.auth,
      updated_at: new Date().toISOString()
    }, { onConflict: "endpoint" });
    if (error) {
      await subscription.unsubscribe();
      throw error;
    }
    updateAnnouncementPushButton(true);
    alert("¡Listo! Este dispositivo recibirá notificaciones cuando se publiquen anuncios.");
  } catch (error) {
    console.error("Error configurando avisos de anuncios:", error);
    alert("No se pudieron configurar los avisos: " + (error.message || "Error desconocido"));
  } finally {
    if (button) button.disabled = false;
  }
}

async function sendAnnouncementPush(title, content) {
  try {
    const { error } = await window.supabaseClient.functions.invoke("send-announcement-push", {
      body: { title, content }
    });
    if (error) console.warn("El anuncio se publicó, pero no se pudieron enviar los avisos push:", error);
  } catch (error) {
    console.warn("El anuncio se publicó; el servicio de avisos no está disponible:", error);
  }
}

function showAppView() {
  document.getElementById("login-view").classList.add("hidden");
  document.getElementById("app-container").classList.remove("hidden");

  const previewBar = document.getElementById("role-preview-bar");
  if (previewBar) previewBar.classList.toggle("hidden", !rolePreviewActive);
  const appContainer = document.getElementById("app-container");
  if (appContainer) appContainer.classList.toggle("role-preview-mode", rolePreviewActive);
  document.getElementById("current-user-name").textContent = currentUser.name;
  const badge = document.getElementById("current-user-role-badge");
  const dashboardRoles = currentUser.roles.length > 1 ? currentUser.roles.filter(role => role !== "miembro") : currentUser.roles;
  badge.textContent = dashboardRoles.map(role => roleDisplayName(role).toUpperCase()).join(" + ");

  applyRolePermissions();
  renderDashboard();
  renderTable();
  renderRequests();
  renderAnnouncements();
  renderBirthdayModule();
  refreshAnnouncementPushButton();
}


async function refreshMinistryModules() {
  if (!currentUser) return;
  const memberModule = document.getElementById("member-ministry-module");
  const reviewModule = document.getElementById("ministry-requests-module");

  if (isMemberOnly() && currentUser.memberId && memberModule) {
    const ownMember = members.find(m => String(m.id) === String(currentUser.memberId));
    let request = null;
    const { data, error } = await window.supabaseClient.rpc("mi_estado_solicitud_ministerio");
    if (error) console.warn("No se pudo consultar el estado de la solicitud de ministerio:", error);
    else request = Array.isArray(data) && data.length ? data[0] : null;

    const eligible = !!ownMember && ownMember.status === "Activo" && (ownMember.ministry || "General") === "General";
    memberModule.classList.toggle("hidden", !eligible);
    const form = document.getElementById("member-ministry-form");
    const pending = document.getElementById("member-ministry-pending");
    const message = document.getElementById("member-ministry-message");
    if (form && pending && message) {
      if (request && request.estado === "pendiente") {
        form.classList.add("hidden");
        pending.classList.remove("hidden");
        message.textContent = "Tu solicitud para " + request.ministerio + " está pendiente de autorización del líder o de Administración.";
      } else {
        pending.classList.add("hidden");
        form.classList.remove("hidden");
        message.textContent = request && request.estado === "rechazado"
          ? "Tu solicitud anterior no fue aprobada. Puedes escoger un ministerio y enviar una nueva solicitud."
          : "Escoge el ministerio al que deseas integrarte. Tu ingreso quedará pendiente hasta ser autorizado.";
      }
    }
  } else if (memberModule) {
    memberModule.classList.add("hidden");
  }

  const canReview = hasRole("admin") || hasRole("lider");
  if (reviewModule) reviewModule.classList.toggle("hidden", !canReview);
  if (canReview && reviewModule) {
    const list = document.getElementById("ministry-requests-list");
    const empty = document.getElementById("ministry-requests-empty");
    const { data, error } = await window.supabaseClient.rpc("listar_solicitudes_ministerio_pendientes");
    if (error) {
      console.warn("No se pudieron cargar las solicitudes de ministerio:", error);
      if (list) list.innerHTML = "";
      if (empty) { empty.textContent = "No se pudieron cargar las solicitudes: " + error.message; empty.classList.remove("hidden"); }
      return;
    }
    if (!list || !empty) return;
    list.innerHTML = "";
    const rows = data || [];
    empty.classList.toggle("hidden", rows.length > 0);
    empty.textContent = "No hay solicitudes pendientes para los ministerios que puedes administrar.";
    rows.forEach(item => {
      const card = document.createElement("article");
      card.className = "rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3";
      const info = document.createElement("div");
      info.innerHTML = '<p class="font-semibold text-slate-900 dark:text-white">' + escapeHtml(item.nombre) + '</p>' +
        '<p class="text-xs text-slate-500 dark:text-slate-400 mt-1">Solicita ingresar a <strong>' + escapeHtml(item.ministerio) + '</strong></p>' +
        '<p class="text-[11px] text-slate-400 mt-1">' + escapeHtml(new Date(item.creado_en).toLocaleString("es-CL")) + '</p>';
      const actions = document.createElement("div");
      actions.className = "flex gap-2 shrink-0";
      const approve = document.createElement("button");
      approve.type = "button"; approve.textContent = "Autorizar";
      approve.className = "px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold";
      approve.addEventListener("click", () => resolveMinistryRequest(item.solicitud_id, true));
      const reject = document.createElement("button");
      reject.type = "button"; reject.textContent = "Rechazar";
      reject.className = "px-3 py-2 rounded-lg border border-rose-300 text-rose-700 dark:text-rose-300 text-xs font-semibold";
      reject.addEventListener("click", () => resolveMinistryRequest(item.solicitud_id, false));
      actions.append(approve, reject);
      card.append(info, actions);
      list.append(card);
    });
  }
}

async function submitMemberMinistryRequest(event) {
  event.preventDefault();
  if (!isMemberOnly() || !currentUser.memberId) return;
  const select = document.getElementById("member-ministry-select");
  const button = document.getElementById("member-ministry-submit");
  const ministry = select ? select.value : "";
  if (!ministry) { alert("Selecciona un ministerio."); return; }
  if (button) { button.disabled = true; button.textContent = "Enviando solicitud..."; }
  try {
    const { error } = await window.supabaseClient.rpc("solicitar_ingreso_ministerio", { p_ministerio: ministry });
    if (error) throw error;
    await refreshMinistryModules();
    alert("Tu solicitud fue enviada. El ministerio aparecerá en tu ficha cuando sea autorizada.");
  } catch (error) {
    alert("No se pudo enviar la solicitud: " + error.message);
  } finally {
    if (button) { button.disabled = false; button.textContent = "Solicitar ingreso"; }
  }
}

async function resolveMinistryRequest(id, approve) {
  const action = approve ? "autorizar" : "rechazar";
  if (!confirm("¿Deseas " + action + " esta solicitud de ministerio?")) return;
  try {
    const { error } = await window.supabaseClient.rpc("resolver_solicitud_ministerio", {
      p_solicitud_id: id, p_aprobar: approve
    });
    if (error) throw error;
    await refreshCloudData();
    renderDashboard(); renderTable(); renderBirthdayModule();
    await refreshMinistryModules();
    alert(approve ? "Ingreso al ministerio autorizado." : "Solicitud rechazada.");
  } catch (error) {
    alert("No se pudo " + action + " la solicitud: " + error.message);
  }
}

async function removeMemberFromMyMinistry() {
  const id = window.currentDetailsMemberId;
  if (!id || !confirm("¿Retirar a este hermano de tu ministerio y devolverlo a General?")) return;
  try {
    const { error } = await window.supabaseClient.rpc("quitar_miembro_de_ministerio", { p_miembro_id: String(id) });
    if (error) throw error;
    await refreshCloudData();
    renderDashboard(); renderTable(); renderBirthdayModule();
    viewDetails(id);
    await refreshMinistryModules();
    alert("El hermano ahora pertenece a General.");
  } catch (error) {
    alert("No se pudo retirar al hermano del ministerio: " + error.message);
  }
}

async function adminAssignMemberMinistry() {
  const id = window.currentDetailsMemberId;
  const select = document.getElementById("view-admin-ministry-select");
  if (!id || !select) return;
  try {
    const { error } = await window.supabaseClient.rpc("admin_asignar_ministerio", {
      p_miembro_id: String(id), p_ministerio: select.value
    });
    if (error) throw error;
    await refreshCloudData();
    renderDashboard(); renderTable(); renderBirthdayModule();
    viewDetails(id);
    await refreshMinistryModules();
    alert("Ministerio actualizado correctamente.");
  } catch (error) {
    alert("No se pudo asignar el ministerio: " + error.message);
  }
}

function startRealtimeSync() {
  stopRealtimeSync();

  realtimeChannel = window.supabaseClient
    .channel("iglesia-renacer-sync")
    .on("postgres_changes",
      { event: "*", schema: "public", table: "miembros_app" },
      scheduleCloudRefresh
    )
    .on("postgres_changes",
      { event: "*", schema: "public", table: "peticiones_oracion" },
      scheduleCloudRefresh
    )
    .on("postgres_changes",
      { event: "*", schema: "public", table: "anuncios" },
      scheduleCloudRefresh
    )
    .on("postgres_changes",
      { event: "*", schema: "public", table: "notas_pastorales" },
      scheduleCloudRefresh
    )
    .on("postgres_changes",
      { event: "*", schema: "public", table: "notas_lideres" },
      scheduleCloudRefresh
    )
    .on("postgres_changes",
      { event: "*", schema: "public", table: "solicitudes_ministerio" },
      scheduleCloudRefresh
    )
    .on("postgres_changes",
      { event: "*", schema: "public", table: "solicitudes_registro_miembros" },
      () => { if (currentUser && hasRole("admin") && !document.getElementById("users-modal").classList.contains("hidden")) loadPendingMemberRequests(); }
    )
    .subscribe(status => {
      if (status === "CHANNEL_ERROR") {
        console.error("No se pudo iniciar la sincronización en tiempo real.");
      }
    });
}

function stopRealtimeSync() {
  if (realtimeRefreshTimer) {
    clearTimeout(realtimeRefreshTimer);
    realtimeRefreshTimer = null;
  }

  if (realtimeChannel) {
    window.supabaseClient.removeChannel(realtimeChannel);
    realtimeChannel = null;
  }
}

function scheduleCloudRefresh() {
  if (realtimeRefreshTimer) clearTimeout(realtimeRefreshTimer);

  realtimeRefreshTimer = setTimeout(async () => {
    if (!currentUser) return;

    try {
      await refreshCloudData();
      renderDashboard();
      renderTable();
      await refreshMinistryModules();
      renderRequests();
      renderAnnouncements();
      renderBirthdayModule();
    } catch (error) {
      console.error("Error sincronizando los datos:", error);
    }
  }, 350);
}

function applyRolePermissions() {
  const isAdmin = hasRole("admin");
  const isServerRestricted = hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor");
  const canManageMembers = (hasRole("admin") || hasRole("pastor") || hasServerMinistryPermissions());
  const canPastoralNotes = isAdmin || hasRole("pastor");
  const canLeaderNotes = canPastoralNotes || hasRole("lider");
  const canViewVisitCards = isAdmin || hasRole("pastor") || hasRole("lider") || hasRole("miembro") || hasRole("hermano") || hasServerMinistryPermissions();
  const visitModule = document.getElementById("visit-cards-module");
  if (visitModule) visitModule.classList.toggle("hidden", !canViewVisitCards);
  const memberTable = document.getElementById("members-table-body");
  const memberSection = memberTable ? memberTable.closest("section") : null;
  if (memberSection) memberSection.classList.toggle("hidden", isServerRestricted);

  const btnAddMember = document.getElementById("btn-add-member");
  const btnAddRequest = document.getElementById("btn-add-request");
  const btnManageUsers = document.getElementById("btn-manage-users");
  const rolePreviewControl = document.getElementById("role-preview-control");
  if (rolePreviewControl) rolePreviewControl.classList.toggle("hidden", !(isAdmin || (!!rolePreviewOriginalUser && rolePreviewOriginalUser.roles?.includes("admin"))));
  const pastoralHistory = document.getElementById("view-pastoral-history-section");
  const leaderHistory = document.getElementById("view-leader-history-section");
  if (pastoralHistory) pastoralHistory.classList.toggle("hidden", !canPastoralNotes);
  if (leaderHistory) leaderHistory.classList.toggle("hidden", !canLeaderNotes);

  // Administración/Pastorado gestionan fichas; el ministerio Servidores puede consultar y crear visitas.
  if (btnAddMember) btnAddMember.classList.toggle("hidden", !canManageMembers);
  const memberStatusInput = document.getElementById("input-status");
  const serverStatusHint = document.getElementById("server-visit-only-hint");
  if (memberStatusInput && isServerRestricted) {
    memberStatusInput.value = "En Visita";
    memberStatusInput.disabled = true;
  } else if (memberStatusInput) {
    memberStatusInput.disabled = false;
  }
  if (serverStatusHint) serverStatusHint.classList.toggle("hidden", !isServerRestricted);
  if (btnAddRequest) btnAddRequest.classList.remove("hidden");

  if (isAdmin) {
    btnManageUsers.classList.remove("hidden");
  } else {
    btnManageUsers.classList.add("hidden");
  }
}

/* USER MANAGEMENT (ADMIN ROLE) */
async function openUsersModal() {
  if (!currentUser || !hasRole("admin")) return;

  try {
    await loadProfilesFromCloud();
    renderUsersTable();
    renderApprovedAccessTable();
    document.getElementById("users-modal").classList.remove("hidden");
    if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
    await loadPendingMemberRequests();
  } catch (error) {
    console.error(error);
    alert("No se pudieron consultar los usuarios: " + error.message);
  }
}

function closeUsersModal() {
  document.getElementById("users-modal").classList.add("hidden");
}

function resetUserForm() {
  alert("Las cuentas se crean en Supabase → Authentication → Users. Después debes vincular su UUID en perfiles_app.");
}

async function handleUserSubmit(event) {
  event.preventDefault();
  alert("Por seguridad, las contraseñas no se crean ni almacenan desde esta página. Crea la cuenta en Supabase → Authentication → Users y luego registra su perfil en perfiles_app.");
}

/* COPIAS DE SEGURIDAD Y RESTAURACIÓN DIRECTAS DE SUPABASE (SOLO ADMIN) */
async function readSupabaseTableForBackup(table) {
  const pageSize = 1000;
  const rows = [];
  for (let offset = 0; ; offset += pageSize) {
    const { data, error } = await window.supabaseClient
      .from(table)
      .select("*")
      .range(offset, offset + pageSize - 1);
    if (error) throw error;
    rows.push(...(data || []));
    if (!data || data.length < pageSize) break;
  }
  return rows;
}

function setSupabaseBackupStatus(message, isError = false) {
  const status = document.getElementById("supabase-backup-status");
  if (!status) return;
  status.textContent = message;
  status.className = "text-xs " + (isError
    ? "text-red-600 dark:text-red-400"
    : "text-slate-500 dark:text-slate-400");
}

const RENACER_BACKUP_TABLES = [
  "anuncios",
  "avisos_congregacion",
  "miembros",
  "miembros_app",
  "notas_antecedentes",
  "notas_lideres",
  "notas_pastorales",
  "perfiles_app",
  "peticiones_oracion",
  "registro_auditoria",
  "solicitudes_registro_miembros",
  "solicitudes_ministerio"
];
const RENACER_BACKUP_BUCKETS = ["profile-photos", "sitio-publico"];

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length)));
  }
  return btoa(binary);
}

async function readStorageBucketForBackup(bucket, folder = "") {
  const files = [];
  const pageSize = 100;
  for (let offset = 0; ; offset += pageSize) {
    const { data, error } = await window.supabaseClient.storage
      .from(bucket)
      .list(folder, { limit: pageSize, offset, sortBy: { column: "name", order: "asc" } });
    if (error) throw new Error("No se pudo listar el almacenamiento " + bucket + ": " + error.message);
    for (const item of data || []) {
      const path = folder ? folder + "/" + item.name : item.name;
      if (item.id === null) {
        files.push(...await readStorageBucketForBackup(bucket, path));
        continue;
      }
      const { data: blob, error: downloadError } = await window.supabaseClient.storage.from(bucket).download(path);
      if (downloadError) throw new Error("No se pudo respaldar " + bucket + "/" + path + ": " + downloadError.message);
      files.push({
        bucket,
        path,
        contentType: item.metadata?.mimetype || blob.type || "application/octet-stream",
        base64: arrayBufferToBase64(await blob.arrayBuffer())
      });
    }
    if (!data || data.length < pageSize) break;
  }
  return files;
}

async function createSupabaseBackup() {
  if (!currentUser || !hasRole("admin")) {
    alert("Solo un administrador puede crear copias de seguridad.");
    return;
  }

  const button = document.querySelector('button[onclick="createSupabaseBackup()"]');
  if (button) button.disabled = true;
  setSupabaseBackupStatus("Consultando todas las tablas y archivos de Supabase...");

  try {
    const tableEntries = await Promise.all(RENACER_BACKUP_TABLES.map(async table => [
      table, await readSupabaseTableForBackup(table)
    ]));
    const data = Object.fromEntries(tableEntries);
    const storageFiles = [];
    for (const bucket of RENACER_BACKUP_BUCKETS) {
      setSupabaseBackupStatus("Respaldando fotografías y archivos: " + bucket + "...");
      storageFiles.push(...await readStorageBucketForBackup(bucket));
    }

    const backup = {
      app: "Iglesia Renacer - Control Congregacional",
      format: "renacer-supabase-backup",
      schemaVersion: 2,
      exportedAt: new Date().toISOString(),
      exportedBy: currentUser.name || "Administrador",
      source: "Supabase",
      includesAuthAccounts: false,
      excludesDevicePushSubscriptions: true,
      data,
      storageFiles
    };

    const dateStr = new Date().toISOString().slice(0, 10);
    const filename = "Iglesia_Renacer_Supabase_Backup_" + dateStr + ".json";
    downloadFile(JSON.stringify(backup), filename, "application/json");
    const totalRows = Object.values(data).reduce((sum, rows) => sum + rows.length, 0);
    setSupabaseBackupStatus(
      "Copia completa creada: " + totalRows + " registros en " + RENACER_BACKUP_TABLES.length +
      " tablas y " + storageFiles.length + " archivos. Guarda este JSON en un lugar seguro: contiene datos personales y notas privadas."
    );
  } catch (error) {
    console.error("Error creando copia de Supabase:", error);
    setSupabaseBackupStatus("No se pudo crear la copia: " + error.message, true);
    alert("No se pudo crear la copia de seguridad: " + error.message);
  } finally {
    if (button) button.disabled = false;
  }
}

async function restoreSupabaseBackup(event) {
  if (!currentUser || !hasRole("admin")) {
    alert("Solo un administrador puede restaurar copias de seguridad.");
    event.target.value = "";
    return;
  }

  const file = event.target.files && event.target.files[0];
  if (!file) return;
  setSupabaseBackupStatus("Validando el archivo de respaldo...");

  try {
    const parsed = JSON.parse(await file.text());
    const data = parsed && parsed.data;
    const validFormat = parsed &&
      parsed.format === "renacer-supabase-backup" &&
      [1, 2].includes(parsed.schemaVersion) &&
      data &&
      Array.isArray(data.miembros_app) &&
      Array.isArray(data.peticiones_oracion) &&
      Array.isArray(data.notas_pastorales);
    if (!validFormat) {
      throw new Error("El archivo no es una copia válida de Iglesia Renacer o su versión no es compatible.");
    }

    const storageFiles = Array.isArray(parsed.storageFiles) ? parsed.storageFiles : [];
    const validFiles = storageFiles.every(item =>
      item && RENACER_BACKUP_BUCKETS.includes(item.bucket) &&
      typeof item.path === "string" && item.path.length > 0 &&
      !item.path.split("/").some(part => part === "..") &&
      typeof item.base64 === "string" &&
      typeof item.contentType === "string"
    );
    if (!validFiles) throw new Error("El respaldo contiene archivos de almacenamiento no válidos.");

    const rowCount = Object.values(data).filter(Array.isArray).reduce((sum, rows) => sum + rows.length, 0);
    const confirmed = confirm(
      "Vas a restaurar desde: " + file.name + "\n\n" +
      "Registros de base de datos: " + rowCount + "\n" +
      "Archivos/fotografías: " + storageFiles.length + "\n\n" +
      "La base de datos se restaurará en una sola transacción. Los registros con el mismo ID se actualizarán; los registros que no estén en el respaldo no se eliminarán. " +
      "Las cuentas de Auth y sus contraseñas no se exportan ni se recrean. Las suscripciones push se volverán a registrar desde cada dispositivo. " +
      "¿Deseas continuar?"
    );
    if (!confirmed) {
      setSupabaseBackupStatus("Restauración cancelada.");
      return;
    }

    // Se cargan primero los archivos. Si un archivo falla, la transacción de base de datos aún no ha comenzado.
    for (let i = 0; i < storageFiles.length; i++) {
      const item = storageFiles[i];
      setSupabaseBackupStatus("Restaurando archivo " + (i + 1) + " de " + storageFiles.length + "...");
      const binary = atob(item.base64);
      const bytes = new Uint8Array(binary.length);
      for (let j = 0; j < binary.length; j++) bytes[j] = binary.charCodeAt(j);
      const blob = new Blob([bytes], { type: item.contentType });
      const { error } = await window.supabaseClient.storage.from(item.bucket).upload(item.path, blob, {
        contentType: item.contentType,
        upsert: true
      });
      if (error) throw new Error("Error restaurando " + item.bucket + "/" + item.path + ": " + error.message);
    }

    setSupabaseBackupStatus("Restaurando registros en una transacción...");
    const { data: restoreResult, error: restoreError } = await window.supabaseClient.rpc(
      "restaurar_respaldo_renacer",
      { p_data: data }
    );
    if (restoreError) throw new Error("La base de datos no se modificó porque falló la transacción: " + restoreError.message);
    if (Array.isArray(data.notas_antecedentes) && data.notas_antecedentes.length) {
      const { error: antecedentRestoreError } = await window.supabaseClient.rpc(
        "restaurar_antecedentes_respaldo",
        { p_rows: data.notas_antecedentes }
      );
      if (antecedentRestoreError) throw new Error("No se pudieron restaurar los antecedentes: " + antecedentRestoreError.message);
    }

    await refreshCloudData();
    renderDashboard();
    renderTable();
    renderRequests();
    renderBirthdayModule();
    await loadProfilesFromCloud();

    setSupabaseBackupStatus("Restauración completada. " + (restoreResult?.rows_restored ?? rowCount) +
      " registros procesados y " + storageFiles.length + " archivos restaurados.");
    alert("Restauración completada correctamente. La base de datos se restauró transaccionalmente y los archivos fueron cargados.");
  } catch (error) {
    console.error("Error restaurando copia de Supabase:", error);
    setSupabaseBackupStatus("No se pudo completar la restauración: " + error.message, true);
    alert("No se pudo completar la restauración: " + error.message +
      "\n\nSi el error ocurrió durante la carga de archivos, algunos archivos podrían haberse cargado antes del fallo. La base de datos se mantiene íntegra si la función de restauración informó un error.");
  } finally {
    event.target.value = "";
  }
}

function exportFullDatabase() {
  if (!currentUser || !hasRole("admin")) return;

  const fullData = {
    app: "Iglesia Renacer - Control Congregacional",
    exportedAt: new Date().toISOString(),
    version: "2.0",
    data: {
      users: users.map(user => ({
        id: user.id,
        name: user.name,
        username: user.username,
        roles: user.roles,
        active: user.active
      })),
      members: members,
      prayerRequests: prayerRequests
    }
  };

  const dateStr = new Date().toISOString().split("T")[0];
  downloadFile(JSON.stringify(fullData, null, 2),
    "Iglesia_Renacer_Backup_" + dateStr + ".json", "application/json");
}

function importFullDatabase(event) {
  if (!currentUser || !hasRole("admin")) return;

  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async function(loadEvent) {
    try {
      const parsed = JSON.parse(loadEvent.target.result);

      if (!parsed.data ||
          !Array.isArray(parsed.data.members) ||
          !Array.isArray(parsed.data.prayerRequests)) {
        alert("El archivo no tiene un formato válido de copia de seguridad.");
        event.target.value = "";
        return;
      }

      const confirmed = confirm(
        "Se importarán " + parsed.data.members.length +
        " miembros y " + parsed.data.prayerRequests.length +
        " peticiones a Supabase. Los perfiles de usuario no se importan. ¿Continuar?"
      );

      if (!confirmed) {
        event.target.value = "";
        return;
      }

      members = parsed.data.members;
      prayerRequests = parsed.data.prayerRequests;

      await saveMembers();
      await saveRequests();
      await refreshCloudData();

      renderDashboard();
      renderTable();
      renderRequests();
      renderBirthdayModule();

      alert("Importación completada. Los registros se sincronizarán con los demás dispositivos.");
    } catch (error) {
      console.error(error);
      alert("No se pudo importar la copia: " + error.message);
      try { await refreshCloudData(); } catch (_) {}
    }

    event.target.value = "";
  };

  reader.readAsText(file);
}

function editUser() {
  alert("La edición de perfiles se administra desde Supabase. No se modifican contraseñas desde esta página.");
}

function deleteUser() {
  alert("Por seguridad, no elimines físicamente cuentas que tengan notas de líderes o historial asociado. Desactiva la cuenta en Supabase Auth y cambia activo a FALSE en perfiles_app; así se conserva la trazabilidad congregacional.");
}

async function approveSignup(userId) {
  if (!currentUser || !hasRole("admin")) return;
  const requestedUser = users.find(user => user.id === userId);
  if (!requestedUser || requestedUser.active || requestedUser.requestStatus !== "pendiente") return;
  if (!confirm("¿Aprobar la cuenta de " + requestedUser.name + "? Se habilitará con el rol " + requestedUser.role + ".")) return;

  const { error } = await window.supabaseClient
    .from("perfiles_app")
    .update({ activo: true, estado_solicitud: "aprobado" })
    .eq("id", userId)
    .eq("activo", false)
    .eq("estado_solicitud", "pendiente");
  if (error) {
    alert("No se pudo aprobar la cuenta: " + error.message);
    return;
  }
  await loadProfilesFromCloud();
  renderUsersTable();
  alert("Cuenta aprobada. El usuario ya puede iniciar sesión con el rol " + requestedUser.role + ".");
}

async function rejectSignup(userId) {
  if (!currentUser || !hasRole("admin")) return;
  const requestedUser = users.find(user => user.id === userId);
  if (!requestedUser || requestedUser.active || requestedUser.requestStatus !== "pendiente") return;
  if (!confirm("¿Rechazar la solicitud de " + requestedUser.name + "? La cuenta quedará bloqueada y no podrá iniciar sesión. El registro de autenticación se conservará en Supabase.")) return;

  const { error } = await window.supabaseClient
    .from("perfiles_app")
    .update({ activo: false, estado_solicitud: "rechazado" })
    .eq("id", userId)
    .eq("activo", false)
    .eq("estado_solicitud", "pendiente");
  if (error) {
    alert("No se pudo rechazar la solicitud: " + error.message);
    return;
  }
  await loadProfilesFromCloud();
  renderUsersTable();
  alert("Solicitud rechazada. La cuenta permanece bloqueada.");
}

async function saveUserRoles(userId) {
  if (!currentUser || !hasRole("admin")) return;
  const selectElement = document.getElementById("user-roles-" + userId);
  if (!selectElement) return;
  const allowedRoles = ["admin", "pastor", "lider", "miembro"];
  const targetUser = users.find(user => user.id === userId);
  const nextRoles = selectElement.value ? [selectElement.value] : [];
  if (!targetUser || userId === currentUser.id || !nextRoles.length || nextRoles.some(role => !allowedRoles.includes(role)) || new Set(nextRoles).size !== nextRoles.length) {
    alert("Selecciona al menos un rol válido. No puedes modificar tu propia asignación."); renderUsersTable(); return;
  }
  if (JSON.stringify([...nextRoles].sort()) === JSON.stringify([...(targetUser.roles || [])].sort())) return;
  if (!confirm("¿Asignar a " + targetUser.name + " el rol " + nextRoles.map(roleDisplayName).join("") + "?")) { renderUsersTable(); return; }
  const { error } = await window.supabaseClient.from("perfiles_app").update({ roles: nextRoles }).eq("id", userId);
  if (error) { alert("No se pudieron actualizar los roles: " + error.message); renderUsersTable(); return; }

  let ministryWarning = "";
  if (nextRoles.includes("pastor") && targetUser.memberId) {
    const { error: ministryError } = await window.supabaseClient.rpc("admin_asignar_ministerio", {
      p_miembro_id: String(targetUser.memberId), p_ministerio: "General"
    });
    if (ministryError) ministryWarning = " El rol se actualizó, pero no se pudo cambiar su ficha a General: " + ministryError.message;
    else await refreshCloudData();
  }
  await loadProfilesFromCloud(); renderUsersTable();
  alert("Roles actualizados." + (nextRoles.includes("pastor") ? " La ficha asociada queda en el ministerio General." : "") + ministryWarning + " El usuario deberá actualizar la página para aplicar los permisos.");
}
async function linkUserToMember(userId, memberId) {
  if (!currentUser || !hasRole("admin")) return;
  const targetUser = users.find(user => user.id === userId);
  if (!targetUser || userId === currentUser.id) {
    renderUsersTable();
    return;
  }

  const normalizedMemberId = memberId || null;
  if (normalizedMemberId) {
    const member = members.find(item => String(item.id) === String(normalizedMemberId));
    if (!member) {
      alert("El miembro seleccionado ya no está disponible. Actualiza los datos.");
      renderUsersTable();
      return;
    }
    const alreadyLinked = users.find(user => user.id !== userId && user.memberId === normalizedMemberId);
    if (alreadyLinked) {
      alert("Este miembro ya está vinculado a otra cuenta (" + alreadyLinked.name + "). Desvincúlalo primero si corresponde.");
      renderUsersTable();
      return;
    }
  }

  const selectedMember = members.find(item => String(item.id) === String(normalizedMemberId));
  const label = selectedMember ? selectedMember.name : "ningún miembro";
  if (!confirm("¿Vincular la cuenta de " + targetUser.name + " con " + label + "?")) {
    renderUsersTable();
    return;
  }

  const { error } = await window.supabaseClient
    .from("perfiles_app")
    .update({ miembro_id: normalizedMemberId })
    .eq("id", userId);
  if (error) {
    alert("No se pudo actualizar la vinculación: " + error.message);
    renderUsersTable();
    return;
  }

  let ministryWarning = "";
  if (normalizedMemberId && (targetUser.roles || []).includes("pastor")) {
    const { error: ministryError } = await window.supabaseClient.rpc("admin_asignar_ministerio", {
      p_miembro_id: String(normalizedMemberId), p_ministerio: "General"
    });
    if (ministryError) ministryWarning = " La vinculación se guardó, pero no se pudo cambiar la ficha a General: " + ministryError.message;
    else await refreshCloudData();
  }
  await loadProfilesFromCloud();
  renderUsersTable();
  alert((normalizedMemberId
    ? "Cuenta vinculada correctamente con el miembro seleccionado."
    : "La cuenta quedó desvinculada del registro de miembros.") + ministryWarning);
}

async function createMemberAccess(memberId) {
  if (!currentUser || !hasRole("admin")) return;
  const member = members.find(item => String(item.id) === String(memberId));
  if (!member) return;
  if (member.status !== "Activo") {
    alert("Primero cambia el estado congregacional a Activo y guarda la ficha.");
    return;
  }
  const email = String(member.email || "").trim().toLowerCase();
  if (!email) {
    alert("Esta ficha no tiene correo. Edita sus datos y registra un correo válido antes de crear el acceso.");
    return;
  }
  if (!confirm("Se habilitará el acceso de " + member.name + " usando " + email + ". Luego se enviará un enlace para que establezca su propia contraseña. ¿Continuar?")) return;
  const button = document.getElementById("view-create-access-button");
  if (button) { button.disabled = true; button.textContent = "Preparando acceso..."; }
  try {
    const { data, error } = await window.supabaseClient.functions.invoke("crear-acceso-miembro", {
      body: { member_id: String(member.id) }
    });
    if (error) throw error;
    if (data?.error) throw new Error(data.error);
    const { error: emailError } = await window.supabaseClient.auth.resetPasswordForEmail(email, {
      redirectTo: new URL("restablecer.html", window.location.href).toString()
    });
    if (emailError) throw emailError;
    await loadProfilesFromCloud();
    renderUsersTable();
    const status = data?.status === "already_linked" ? "La cuenta ya estaba vinculada." : "La cuenta quedó creada y vinculada.";
    alert(status + " Enviamos un enlace seguro a " + email + " para que establezca o cambie su contraseña. No necesitas conocer su clave.");
  } catch (error) {
    console.error("Error creando acceso de miembro:", error);
    alert("No se pudo completar el acceso: " + (error.message || "Error inesperado."));
  } finally {
    if (button) button.disabled = false;
    viewDetails(member.id);
  }
}

async function resetUserPassword(userId) {
  if (!currentUser || !hasRole("admin")) return;
  const targetUser = users.find(user => user.id === userId);
  if (!targetUser || !targetUser.username || !String(targetUser.username).includes("@")) {
    alert("No hay un correo electrónico válido asociado a esta cuenta.");
    return;
  }
  if (!confirm("¿Enviar un enlace para restablecer la contraseña de " + targetUser.name + " (" + targetUser.username + ")?")) return;

  try {
    const { error } = await window.supabaseClient.auth.resetPasswordForEmail(targetUser.username, {
      redirectTo: new URL("restablecer.html", window.location.href).toString()
    });
    if (error) throw error;
    alert("Se envió un enlace de restablecimiento al correo de " + targetUser.name + ". El usuario deberá abrirlo y elegir una contraseña nueva.");
  } catch (error) {
    console.error("Error enviando recuperación de contraseña:", error);
    alert("No se pudo enviar el enlace de restablecimiento: " + error.message);
  }
}

function renderUsersTable() {
  const tbody = document.getElementById("users-table-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  const roleChoices = [
    { value: "miembro", label: "Miembro" },
    { value: "lider", label: "Líder" },
    { value: "pastor", label: "Pastor" },
    { value: "admin", label: "Administrador" }
  ];
  const ministryChoices = ["General", "Alabanza", "Servidor", "Niños", "Jóvenes", "Oración", "Evangelismo", "Redes", "Damas", "Matrimonio", "Hombres"];

  // La asignación de roles solo debe mostrar fichas con estado Activo.
  members.filter(member => member.status === "Activo")
    .sort((a, b) => String(a.name || "").localeCompare(String(b.name || ""), "es"))
    .forEach(member => {
    const linkedUser = users.find(user => String(user.memberId) === String(member.id));
    const tr = document.createElement("tr");
    tr.className = "hover:bg-slate-50 dark:hover:bg-slate-700/50";
    const name = document.createElement("td");
    name.className = "py-3 px-3 font-semibold text-slate-900 dark:text-white";
    name.dataset.label = "Miembro";
    name.textContent = member.name || "Sin nombre";

    const roleCell = document.createElement("td");
    roleCell.className = "py-2.5 px-3 min-w-[145px]";
    roleCell.dataset.label = "Rol de acceso";
    const roleSelect = document.createElement("select");
    roleSelect.className = "w-full max-w-xs px-2.5 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-xs";
    roleSelect.setAttribute("aria-label", "Rol de acceso de " + (member.name || "miembro"));
    const currentRole = linkedUser ? ((linkedUser.roles && linkedUser.roles[0]) || linkedUser.role || "miembro") : "miembro";
    roleChoices.forEach(choice => {
      const option = document.createElement("option");
      option.value = choice.value;
      option.textContent = choice.label;
      if (choice.value === "lider" && (member.status !== "Activo" || !member.ministry || member.ministry === "General")) {
        option.disabled = true;
        option.textContent = "Líder (requiere ministerio activo)";
      }
      roleSelect.appendChild(option);
    });
    roleSelect.value = roleChoices.some(choice => choice.value === currentRole) ? currentRole : "miembro";
    roleSelect.disabled = !linkedUser || linkedUser.id === currentUser.id;
    if (linkedUser) roleSelect.id = "member-role-" + member.id;
    roleCell.appendChild(roleSelect);

    const ministryCell = document.createElement("td");
    ministryCell.className = "py-2.5 px-3 min-w-[155px]";
    ministryCell.dataset.label = "Ministerio asignado";
    const ministrySelect = document.createElement("select");
    ministrySelect.className = "w-full max-w-xs px-2.5 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-xs";
    ministrySelect.setAttribute("aria-label", "Ministerio asignado de " + (member.name || "miembro"));
    ministryChoices.forEach(ministry => {
      const option = document.createElement("option");
      option.value = ministry;
      option.textContent = ministry;
      if (currentRole === "lider" && ministry === "General") option.disabled = true;
      ministrySelect.appendChild(option);
    });
    ministrySelect.value = ministryChoices.includes(member.ministry) ? member.ministry : "General";
    ministrySelect.disabled = !linkedUser || linkedUser.id === currentUser.id || member.status !== "Activo";
    if (linkedUser) ministrySelect.id = "member-ministry-" + member.id;
    ministryCell.appendChild(ministrySelect);
    if (member.status !== "Activo") {
      const hint = document.createElement("p");
      hint.className = "mt-1 text-[10px] text-slate-500";
      hint.textContent = "Solo miembros activos pueden cambiar de ministerio";
      ministryCell.appendChild(hint);
    }

    if (linkedUser && linkedUser.id !== currentUser.id) {
      const save = document.createElement("button");
      save.type = "button";
      save.className = "ml-1 mt-1 sm:mt-0 px-3 py-2 rounded-lg bg-church-800 hover:bg-church-900 text-white text-xs font-semibold";
      save.textContent = "Guardar";
      save.addEventListener("click", () => saveMemberRole(member.id));
      roleCell.appendChild(save);
    } else if (linkedUser && linkedUser.id === currentUser.id) {
      const note = document.createElement("p");
      note.className = "mt-1 text-[10px] text-amber-600 dark:text-amber-400";
      note.textContent = "No puedes cambiar tu propio rol ni ministerio";
      roleCell.appendChild(note);
    }

    const accountCell = document.createElement("td");
    accountCell.className = "py-3 px-3 text-xs";
    accountCell.dataset.label = "Cuenta";
    accountCell.textContent = linkedUser
      ? (linkedUser.active ? "Cuenta activa" : "Cuenta pendiente/inactiva") + " · " + (linkedUser.username || "")
      : "Sin cuenta vinculada";
    accountCell.classList.add(linkedUser ? "text-slate-600" : "text-amber-600", "dark:text-slate-400");
    tr.append(name, roleCell, ministryCell, accountCell);
    tbody.appendChild(tr);
  });
}

async function saveMemberRole(memberId) {
  if (!currentUser || !hasRole("admin")) return;
  const member = members.find(item => String(item.id) === String(memberId));
  const linkedUser = users.find(user => String(user.memberId) === String(memberId));
  const roleSelect = document.getElementById("member-role-" + memberId);
  const ministrySelect = document.getElementById("member-ministry-" + memberId);
  const allowedRoles = ["admin", "pastor", "lider", "miembro"];
  const allowedMinistries = ["General", "Alabanza", "Servidor", "Niños", "Jóvenes", "Oración", "Evangelismo", "Redes", "Damas", "Matrimonio", "Hombres"];
  if (!member || !linkedUser || !roleSelect || !ministrySelect || linkedUser.id === currentUser.id ||
      !allowedRoles.includes(roleSelect.value) || !allowedMinistries.includes(ministrySelect.value)) {
    alert("No se puede guardar: verifica la cuenta vinculada y las asignaciones.");
    return;
  }

  const nextRole = roleSelect.value;
  const nextMinistry = ministrySelect.value;
  const previousRole = (linkedUser.roles && linkedUser.roles[0]) || linkedUser.role || "miembro";
  const previousMinistry = member.ministry || "General";
  if (nextRole === "lider" && (member.status !== "Activo" || nextMinistry === "General")) {
    alert("Para asignar el rol Líder, la ficha debe estar Activa y tener un ministerio distinto de General.");
    return;
  }
  if (member.status !== "Activo" && nextMinistry !== previousMinistry) {
    alert("Solo puedes cambiar el ministerio de un miembro con estado Activo.");
    return;
  }
  if (nextRole === previousRole && nextMinistry === previousMinistry) return;

  const changes = [];
  if (nextRole !== previousRole) changes.push("rol " + roleDisplayName(nextRole));
  if (nextMinistry !== previousMinistry) changes.push("ministerio " + nextMinistry);
  if (!confirm("Guardar para " + member.name + ": " + changes.join(" y ") + "?")) {
    renderUsersTable();
    return;
  }

  const updateRole = async () => {
    if (nextRole === previousRole) return;
    const { error } = await window.supabaseClient.from("perfiles_app")
      .update({ roles: [nextRole] }).eq("id", linkedUser.id);
    if (error) throw error;
  };
  const updateMinistry = async () => {
    if (nextMinistry === previousMinistry) return;
    const { error } = await window.supabaseClient.rpc("admin_asignar_ministerio", {
      p_miembro_id: String(member.id),
      p_ministerio: nextMinistry
    });
    if (error) throw error;
  };

  try {
    // Primero se retira el rol de líder antes de permitir General; en los demás casos
    // se asigna primero el ministerio para que nunca exista un líder sin ministerio.
    if (previousRole === "lider" && nextRole !== "lider" && nextMinistry === "General") {
      await updateRole();
      await updateMinistry();
    } else {
      await updateMinistry();
      await updateRole();
    }
    await refreshCloudData();
    await loadProfilesFromCloud();
    renderUsersTable();
    alert("Rol y ministerio actualizados correctamente. La persona deberá actualizar la página para aplicar los permisos.");
  } catch (error) {
    console.error("No se pudo actualizar rol/ministerio:", error);
    await refreshCloudData().catch(() => {});
    await loadProfilesFromCloud().catch(() => {});
    renderUsersTable();
    alert("No se pudo completar la asignación: " + error.message);
  }
}



function renderApprovedAccessTable() {
  const tbody = document.getElementById("approved-users-table-body");
  const status = document.getElementById("approved-users-status");
  if (!tbody) return;
  tbody.innerHTML = "";
  const approved = users.filter(user => user.active === true && user.requestStatus === "aprobado");
  if (!approved.length) {
    if (status) status.textContent = "Todavía no hay cuentas aprobadas.";
    return;
  }
  if (status) status.textContent = "Cuentas aprobadas: " + approved.length + ".";
  approved.forEach(user => {
    const member = members.find(item => String(item.id) === String(user.memberId));
    const roles = (user.roles && user.roles.length ? user.roles : (user.role ? [user.role] : []))
      .map(roleDisplayName).join(" · ") || "Sin rol";
    const tr = document.createElement("tr");
    tr.className = "hover:bg-slate-50 dark:hover:bg-slate-700/50";
    [user.name || "Sin nombre", user.username || "Sin usuario", roles, member ? member.name : "Sin ficha asociada"].forEach((value, index) => {
      const td = document.createElement("td");
      td.className = "px-3 py-3 " + (index === 1 ? "font-mono text-xs text-slate-500" : "text-sm text-slate-700 dark:text-slate-200");
      td.textContent = value;
      tr.appendChild(td);
    });
    const action = document.createElement("td");
    action.className = "px-3 py-3 text-right";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-blue-700 hover:bg-blue-800 text-white text-xs font-semibold";
    button.textContent = "Enviar enlace de reseteo";
    button.disabled = !user.username || !String(user.username).includes("@");
    button.addEventListener("click", () => resetUserPassword(user.id));
    action.appendChild(button);
    tr.appendChild(action);
    tbody.appendChild(tr);
  });
}

/* SOLICITUDES PÚBLICAS DE REGISTRO DE MIEMBROS (SOLO ADMIN PARA REVISAR) */
async function loadPendingMemberRequests() {
  if (!currentUser || !hasRole("admin")) return;
  const status = document.getElementById("member-requests-status");
  const tbody = document.getElementById("member-requests-table-body");
  if (!status || !tbody) return;
  status.textContent = "Consultando solicitudes pendientes...";
  tbody.innerHTML = "";
  try {
    const { data, error } = await window.supabaseClient
      .from("solicitudes_registro_miembros")
      .select("id,name,phone,email,address,marital_status,spouse_name,ministry,baptized,birthday,created_at")
      .eq("estado_solicitud", "pendiente")
      .order("created_at", { ascending: true });
    if (error) throw error;
    if (!data || data.length === 0) {
      status.textContent = "No hay solicitudes pendientes.";
      return;
    }
    data.forEach(request => {
      const tr = document.createElement("tr");
      tr.className = "align-top";
      const dateLabel = request.created_at ? new Date(request.created_at).toLocaleString("es-CL") : "—";
      const contact = [request.phone, request.email, request.address].filter(Boolean).join(" · ");
      const congregational = [
        request.marital_status || "—",
        request.spouse_name ? "Pareja: " + request.spouse_name : "",
        "Ministerio: " + (request.ministry || "General"),
        "Bautizado: " + (request.baptized || "No"),
        request.birthday ? "Nacimiento: " + request.birthday : ""
      ].filter(Boolean).join(" · ");
      tr.innerHTML =
        '<td class="p-2.5"><div class="font-semibold text-slate-800 dark:text-white">' + escapeHtml(request.name) + '</div><div class="text-[10px] text-slate-400 mt-1">' + escapeHtml(dateLabel) + '</div></td>' +
        '<td class="p-2.5 text-slate-600 dark:text-slate-300">' + escapeHtml(contact || "—") + '</td>' +
        '<td class="p-2.5 text-slate-600 dark:text-slate-300 whitespace-normal">' + escapeHtml(congregational) + '</td>' +
        '<td class="p-2.5"><div class="flex justify-end gap-1.5"><button type="button" onclick="approvePublicMemberRequest(\'' + escapeHtml(request.id) + '\')" class="px-2.5 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-700 text-white font-semibold">Aprobar</button><button type="button" onclick="rejectPublicMemberRequest(\'' + escapeHtml(request.id) + '\')" class="px-2.5 py-1.5 rounded-md bg-rose-600 hover:bg-rose-700 text-white font-semibold">Rechazar</button></div></td>';
      tbody.appendChild(tr);
    });
    status.textContent = "Solicitudes pendientes: " + data.length + ". Al aprobar, el registro se incorporará a la base de miembros.";
  } catch (error) {
    console.error("Error consultando solicitudes de miembros:", error);
    status.textContent = "No se pudieron cargar las solicitudes. Verifica que hayas ejecutado la migración SQL: " + error.message;
  }
}

async function approvePublicMemberRequest(requestId) {
  if (!currentUser || !hasRole("admin")) return;
  if (!confirm("¿Aprobar esta solicitud? Se incorporarán los datos del hermano al registro oficial de miembros.")) return;
  try {
    const { error } = await window.supabaseClient.rpc("aprobar_solicitud_registro_miembro", {
      p_solicitud_id: requestId
    });
    if (error) throw error;
    await refreshCloudData();
    renderDashboard();
    renderTable();
    renderBirthdayModule();
    await loadPendingMemberRequests();
    alert("Solicitud aprobada. El hermano ya forma parte del registro oficial.");
  } catch (error) {
    console.error("Error aprobando solicitud de miembro:", error);
    alert("No se pudo aprobar la solicitud: " + error.message);
  }
}

async function rejectPublicMemberRequest(requestId) {
  if (!currentUser || !hasRole("admin")) return;
  if (!confirm("¿Rechazar esta solicitud? No se incorporará a la lista oficial de miembros.")) return;
  try {
    const { data, error } = await window.supabaseClient
      .from("solicitudes_registro_miembros")
      .update({
        estado_solicitud: "rechazado",
        reviewed_at: new Date().toISOString(),
        reviewed_by: currentUser.id
      })
      .eq("id", requestId)
      .eq("estado_solicitud", "pendiente")
      .select("id")
      .maybeSingle();
    if (error) throw error;
    if (!data) throw new Error("La solicitud ya fue revisada o no existe.");
    await loadPendingMemberRequests();
    alert("Solicitud rechazada. No se agregó a la base de miembros.");
  } catch (error) {
    console.error("Error rechazando solicitud de miembro:", error);
    alert("No se pudo rechazar la solicitud: " + error.message);
  }
}

/* AUDITORÍA (SOLO ADMINISTRADORES) */
async function openAuditModal() {
  if (!currentUser || !hasRole("admin")) return;

  const modal = document.getElementById("audit-modal");
  modal.classList.remove("hidden");
  await loadAuditLog();
}

function closeAuditModal() {
  document.getElementById("audit-modal").classList.add("hidden");
}

async function loadAuditLog() {
  if (!currentUser || !hasRole("admin")) return;

  const tbody = document.getElementById("audit-table-body");
  const status = document.getElementById("audit-status");
  tbody.innerHTML = "";
  status.textContent = "Cargando registros...";

  try {
    const { data, error } = await window.supabaseClient
      .from("registro_auditoria")
      .select("id,created_at,actor_name,actor_role,action,entity_table,entity_id,changed_fields")
      .order("created_at", { ascending: false })
      .limit(200);

    if (error) throw error;

    if (!data || !data.length) {
      status.textContent = "Todavía no hay eventos registrados.";
      return;
    }

    data.forEach(entry => {
      const tr = document.createElement("tr");
      tr.className = "border-b border-slate-100 dark:border-slate-700";
      const date = new Date(entry.created_at);
      const dateLabel = Number.isNaN(date.getTime())
        ? entry.created_at
        : date.toLocaleString("es-CL", { dateStyle: "short", timeStyle: "short" });
      const actionLabels = { INSERT: "Creación", UPDATE: "Modificación", DELETE: "Eliminación" };
      const entityLabels = {
        miembros_app: "Miembros",
        peticiones_oracion: "Peticiones",
        perfiles_app: "Usuarios",
        notas_pastorales: "Notas pastorales"
      };
      const fields = Array.isArray(entry.changed_fields) ? entry.changed_fields.join(", ") : "";
      [
        dateLabel,
        entry.actor_name || "Sistema",
        entry.actor_role || "sistema",
        actionLabels[entry.action] || entry.action,
        entityLabels[entry.entity_table] || entry.entity_table,
        entry.entity_id || "—",
        fields || "—"
      ].forEach(value => {
        const td = document.createElement("td");
        td.className = "px-3 py-2 align-top text-slate-600 dark:text-slate-300";
        td.textContent = String(value);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });

    status.textContent = "Mostrando los últimos " + data.length + " eventos.";
  } catch (error) {
    console.error("Error consultando auditoría:", error);
    status.textContent = "No se pudo consultar la auditoría: " + error.message;
  }
}

/* ANNOUNCEMENTS MODULE */
function canManageAnnouncements() {
  return !!currentUser && (hasRole("admin") || hasRole("pastor"));
}

function formatAnnouncementDate(value) {
  if (!value) return "";
  return new Date(value).toLocaleString("es-CL", {
    day: "2-digit", month: "long", year: "numeric",
    hour: "2-digit", minute: "2-digit"
  });
}

function renderAnnouncements() {
  const container = document.getElementById("announcements-list");
  const empty = document.getElementById("announcements-empty");
  const createButton = document.getElementById("btn-new-announcement");
  if (!container || !empty || !currentUser) return;

  if (createButton) createButton.classList.toggle("hidden", !canManageAnnouncements());
  container.innerHTML = "";

  if (!announcements.length) {
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");

  announcements.forEach(item => {
    const card = document.createElement("article");
    card.className = "rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/60 p-4 sm:p-5";
    const header = document.createElement("div");
    header.className = "flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2";
    const heading = document.createElement("div");
    heading.className = "min-w-0";
    const title = document.createElement("h4");
    title.className = "font-bold text-slate-900 dark:text-white text-base";
    title.textContent = item.titulo;
    const meta = document.createElement("p");
    meta.className = "text-[11px] text-slate-500 dark:text-slate-400 mt-1";
    const creatorName = String(item.creado_por_nombre || "Usuario registrado");
    meta.textContent = "Publicado el " + formatAnnouncementDate(item.creado_en) + " · Creado por " + creatorName;
    heading.append(title, meta);
    header.appendChild(heading);

    if (canManageAnnouncements()) {
      const actions = document.createElement("div");
      actions.className = "flex items-center gap-2 shrink-0";
      const edit = document.createElement("button");
      edit.type = "button";
      edit.className = "text-xs px-3 py-1.5 rounded-lg bg-blue-50 text-blue-700 hover:bg-blue-100 dark:bg-blue-900/30 dark:text-blue-300";
      edit.textContent = "Editar";
      edit.addEventListener("click", () => openAnnouncementModal(item.id));
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "text-xs px-3 py-1.5 rounded-lg bg-rose-50 text-rose-700 hover:bg-rose-100 dark:bg-rose-900/30 dark:text-rose-300";
      remove.textContent = "Eliminar";
      remove.addEventListener("click", () => deleteAnnouncement(item.id));
      actions.append(edit, remove);
      header.appendChild(actions);
    }

    const body = document.createElement("p");
    body.className = "mt-4 text-sm text-slate-700 dark:text-slate-200 whitespace-pre-wrap break-words";
    body.textContent = item.contenido;
    card.append(header, body);
    container.appendChild(card);
  });
  if (window.lucide) if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

async function refreshAnnouncements() {
  const button = document.getElementById("refresh-announcements-button");
  const icon = document.getElementById("refresh-announcements-icon");
  const label = document.getElementById("refresh-announcements-label");
  if (!currentUser || !window.supabaseClient) return;

  if (button) button.disabled = true;
  if (icon) icon.classList.add("animate-spin");
  if (label) label.textContent = "Actualizando...";

  try {
    const { data, error } = await window.supabaseClient
      .from("anuncios")
      .select("*")
      .order("creado_en", { ascending: false });
    if (error) throw error;
    announcements = data || [];
    renderAnnouncements();
  } catch (error) {
    console.error("No se pudieron actualizar los anuncios:", error);
    alert("No fue posible actualizar los anuncios. Revisa tu conexión e inténtalo nuevamente.");
  } finally {
    if (button) button.disabled = false;
    if (icon) icon.classList.remove("animate-spin");
    if (label) label.textContent = "Actualizar";
  }
}

function openAnnouncementModal(id = "") {
  if (!canManageAnnouncements()) return;
  const form = document.getElementById("announcement-form");
  form.reset();
  document.getElementById("announcement-id").value = "";
  document.getElementById("announcement-modal-title").textContent = "Nuevo anuncio";
  if (id) {
    const item = announcements.find(entry => entry.id === id);
    if (!item) return;
    document.getElementById("announcement-id").value = item.id;
    document.getElementById("announcement-title").value = item.titulo;
    document.getElementById("announcement-content").value = item.contenido;
    document.getElementById("announcement-modal-title").textContent = "Editar anuncio";
  }
  document.getElementById("announcement-modal").classList.remove("hidden");
  if (window.lucide) if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

function closeAnnouncementModal() {
  document.getElementById("announcement-modal").classList.add("hidden");
}

async function handleAnnouncementSubmit(event) {
  event.preventDefault();
  if (!canManageAnnouncements()) return;

  const id = document.getElementById("announcement-id").value;
  const titulo = document.getElementById("announcement-title").value.trim();
  const contenido = document.getElementById("announcement-content").value.trim();
  if (titulo.length < 3 || contenido.length < 3) {
    alert("El título y el contenido deben tener al menos 3 caracteres.");
    return;
  }

  const button = document.getElementById("announcement-save");
  button.disabled = true;
  button.textContent = "Guardando...";
  try {
    let query;
    if (id) {
      query = window.supabaseClient.from("anuncios").update({
        titulo, contenido, actualizado_en: new Date().toISOString()
      }).eq("id", id);
    } else {
      query = window.supabaseClient.from("anuncios").insert({
        titulo, contenido, creado_por: currentUser.id, creado_por_nombre: currentUser.name || "Usuario registrado"
      });
    }
    const { error } = await query;
    if (error) throw error;
    const { data, error: readError } = await window.supabaseClient
      .from("anuncios").select("*").order("creado_en", { ascending: false });
    if (readError) throw readError;
    announcements = data || [];
    renderAnnouncements();
    closeAnnouncementModal();
    if (!id) await sendAnnouncementPush(titulo, contenido);
  } catch (error) {
    console.error("Error guardando anuncio:", error);
    alert("No se pudo guardar el anuncio: " + error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Publicar anuncio";
  }
}

async function deleteAnnouncement(id) {
  if (!canManageAnnouncements()) return;
  const item = announcements.find(entry => entry.id === id);
  if (!item || !confirm("¿Eliminar el anuncio \"" + item.titulo + "\"? Esta acción no se puede deshacer.")) return;
  const { error } = await window.supabaseClient.from("anuncios").delete().eq("id", id);
  if (error) {
    alert("No se pudo eliminar el anuncio: " + error.message);
    return;
  }
  announcements = announcements.filter(entry => entry.id !== id);
  renderAnnouncements();
}

/* RENDER DASHBOARD & METRICS */
/* RENDER DASHBOARD & METRICS */
function renderPersonalWelcomeCard() {
  const nameNode = document.getElementById("welcome-member-name");
  const subtitleNode = document.getElementById("welcome-member-subtitle");
  const avatar = document.getElementById("welcome-member-avatar");
  const initialsNode = document.getElementById("welcome-member-initials");
  const ministryNode = document.getElementById("welcome-member-ministry");
  const roleNode = document.getElementById("welcome-member-role");
  const statusNode = document.getElementById("welcome-member-status");
  const profileButton = document.getElementById("welcome-view-profile");
  if (!nameNode || !currentUser) return;

  const linkedMember = currentUser.memberId
    ? members.find(member => String(member.id) === String(currentUser.memberId))
    : null;
  const displayName = linkedMember ? linkedMember.name : (currentUser.name || "Hermano");
  const initials = displayName.split(/\s+/).filter(Boolean).map(part => part[0]).slice(0, 2).join("").toUpperCase() || "R";

  nameNode.textContent = displayName;
  subtitleNode.textContent = linkedMember
    ? "Qué bueno tenerte en casa. Este es tu espacio en la congregación."
    : "Tu cuenta está activa en el sistema congregacional.";

  if (linkedMember && linkedMember.avatar) {
    avatar.src = linkedMember.avatar;
    avatar.alt = "Fotografía de " + displayName;
    avatar.classList.remove("hidden");
    initialsNode.classList.add("hidden");
  } else {
    avatar.removeAttribute("src");
    avatar.classList.add("hidden");
    initialsNode.textContent = initials;
    initialsNode.classList.remove("hidden");
  }

  const assignedRoles = Array.isArray(currentUser.roles) ? currentUser.roles : (currentUser.role ? [currentUser.role] : []);
  roleNode.textContent = assignedRoles.length ? assignedRoles.map(role => roleDisplayName(role).toUpperCase()).join(" + ") : "USUARIO";
  roleNode.classList.toggle("hidden", !roleNode.textContent);

  ministryNode.textContent = linkedMember ? (linkedMember.ministry || "General") : "";
  ministryNode.classList.toggle("hidden", !linkedMember);
  statusNode.textContent = linkedMember ? (linkedMember.status || "Activo") : "";
  statusNode.classList.toggle("hidden", !linkedMember);
  statusNode.className = "px-3 py-1 rounded-full text-xs font-semibold " +
    (linkedMember && linkedMember.status === "Activo"
      ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-300"
      : "bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-200");

  profileButton.classList.toggle("hidden", !linkedMember);
  profileButton.classList.toggle("flex", !!linkedMember);
}

function viewCurrentMemberProfile() {
  if (!currentUser || !currentUser.memberId) return;
  const linkedMember = members.find(member => String(member.id) === String(currentUser.memberId));
  if (linkedMember) viewDetails(linkedMember.id);
}

function canViewVisitsModule() {
  return !!(currentUser && (hasRole("admin") || hasRole("pastor") || hasRole("lider") || hasRole("miembro") || hasRole("hermano") || hasServerMinistryPermissions()));
}

function canDeleteVisitCards() {
  return !!(currentUser && (hasRole("admin") || hasRole("pastor") || hasServerMinistryPermissions()));
}

function renderVisitCards() {
  const module = document.getElementById("visit-cards-module");
  const container = document.getElementById("visit-cards-list");
  const empty = document.getElementById("visit-cards-empty");
  const count = document.getElementById("visit-cards-count");
  const archivedContainer = document.getElementById("visit-cards-archived-list");
  const archivedSection = document.getElementById("visit-cards-archived-section");
  const archivedCount = document.getElementById("visit-cards-archived-count");
  if (!module || !container || !empty || !count) return;
  const canView = canViewVisitsModule();
  module.classList.toggle("hidden", !canView);
  if (!canView) {
    container.replaceChildren();
    if (archivedContainer) archivedContainer.replaceChildren();
    return;
  }

  const now = Date.now();
  const visitRecords = visitCards.filter(member => member.status === "En Visita");
  const isRecentVisit = member => {
    const createdAt = member.createdAt ? new Date(member.createdAt).getTime() : NaN;
    return Number.isFinite(createdAt) && createdAt > now - 24 * 60 * 60 * 1000;
  };
  const activeVisits = visitRecords.filter(isRecentVisit);
  const archivedVisits = visitRecords.filter(member => !isRecentVisit(member));

  count.textContent = activeVisits.length + (activeVisits.length === 1 ? " visita activa" : " visitas activas");
  container.replaceChildren();
  empty.classList.toggle("hidden", activeVisits.length > 0);
  if (archivedSection) archivedSection.classList.toggle("hidden", archivedVisits.length === 0);
  if (archivedCount) archivedCount.textContent = String(archivedVisits.length);
  if (archivedContainer) archivedContainer.replaceChildren();

  const renderCard = (member, archived = false) => {
    const card = document.createElement("article");
    card.className = "relative overflow-hidden rounded-2xl border " +
      (archived
        ? "border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50"
        : "border-amber-200 dark:border-amber-700/50 bg-gradient-to-br from-white via-amber-50/70 to-white dark:from-slate-800 dark:via-slate-800 dark:to-slate-900") +
      " p-5 shadow-sm";
    const initials = (member.name || "?").trim().split(/\\s+/).map(part => part[0]).slice(0,2).join("").toUpperCase();
    const inviter = member.inviterName || "No especificado";
    const relationship = member.inviterRelationship || "No especificado";
    const createdAt = member.createdAt ? new Date(member.createdAt) : null;
    const dateLabel = createdAt && !Number.isNaN(createdAt.getTime())
      ? createdAt.toLocaleString("es-CL", { dateStyle: "short", timeStyle: "short" })
      : "Fecha de creación no disponible";
    card.innerHTML = `
      <div class="relative flex items-start gap-3">
        <div class="w-12 h-12 shrink-0 rounded-xl ${archived ? "bg-slate-200 text-slate-600 dark:bg-slate-700 dark:text-slate-300" : "bg-church-900 text-amber-300"} flex items-center justify-center font-bold text-sm">${escapeHtml(initials)}</div>
        <div class="min-w-0 flex-1">
          <p class="text-[10px] uppercase tracking-[0.18em] font-bold ${archived ? "text-slate-500" : "text-amber-700 dark:text-amber-400"}">${archived ? "Visita archivada" : "Nueva visita"}</p>
          <h4 class="font-bold text-slate-900 dark:text-white text-lg leading-tight break-words">${escapeHtml(member.name || "Sin nombre")}</h4>
          <p class="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Creada: ${escapeHtml(dateLabel)}</p>
        </div>
        <span class="shrink-0 text-[10px] font-bold px-2 py-1 rounded-full ${archived ? "bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-300" : "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-300"}">${archived ? "Archivada" : "En Visita"}</span>
      </div>
      <div class="relative mt-5 space-y-3 border-t border-slate-200/70 dark:border-slate-700 pt-4">
        <div class="flex items-start gap-2"><i data-lucide="user-round-plus" class="w-4 h-4 mt-0.5 text-amber-600 shrink-0"></i><div class="min-w-0"><p class="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">Invitado por</p><p class="text-sm font-semibold text-slate-800 dark:text-slate-100 break-words">${escapeHtml(inviter)}</p></div></div>
        <div class="flex items-start gap-2"><i data-lucide="heart-handshake" class="w-4 h-4 mt-0.5 text-amber-600 shrink-0"></i><div class="min-w-0"><p class="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-semibold">Parentesco / relación</p><p class="text-sm text-slate-700 dark:text-slate-300 break-words">${escapeHtml(relationship)}</p></div></div>
      </div>
      ${canDeleteVisitCards() ? `<div class="relative mt-4 pt-3 border-t border-slate-200/70 dark:border-slate-700 flex justify-end"><button type="button" onclick="deleteVisitCard('${escapeHtml(String(member.id))}')" class="inline-flex items-center gap-1.5 text-xs font-semibold text-rose-600 hover:text-rose-700 dark:text-rose-400"><i data-lucide="trash-2" class="w-3.5 h-3.5"></i> Eliminar tarjeta</button></div>` : ""}
    `;
    return card;
  };

  activeVisits.forEach(member => container.appendChild(renderCard(member)));
  if (archivedContainer) archivedVisits.forEach(member => archivedContainer.appendChild(renderCard(member, true)));
  if (window.lucide && typeof window.lucide.createIcons === "function") window.lucide.createIcons();
}

async function refreshVisitCards() {
  if (!canViewVisitsModule()) return;
  try {
    await refreshCloudData();
    renderDashboard();
  } catch (error) {
    console.error("Error actualizando tarjetas de visitas:", error);
    alert("No se pudieron actualizar las tarjetas: " + error.message);
  }
}

async function deleteVisitCard(id) {
  if (!canDeleteVisitCards()) {
    alert("Solo Administradores, Pastores y el ministerio Servidor pueden eliminar tarjetas de visitas.");
    return;
  }
  const visit = visitCards.find(member => String(member.id) === String(id) && member.status === "En Visita");
  if (!visit) return;
  if (!confirm("¿Eliminar la tarjeta de " + visit.name + "? Esta acción también eliminará su ficha de visita del registro congregacional.")) return;
  const { error } = await window.supabaseClient.from("miembros_app").delete().eq("id", id).eq("status", "En Visita");
  if (error) {
    alert("No se pudo eliminar la tarjeta: " + error.message);
    return;
  }
  visitCards = visitCards.filter(member => String(member.id) !== String(id));
  const serverOnly = hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor");
  if (!serverOnly) {
    members = members.filter(member => String(member.id) !== String(id));
    renderTable();
    renderBirthdayModule();
  }
  renderDashboard();
}

function countRecentVisitCards() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  return visitCards.filter(member => {
    if (member.status !== "En Visita" || !member.createdAt) return false;
    const createdAt = new Date(member.createdAt).getTime();
    return Number.isFinite(createdAt) && createdAt > cutoff;
  }).length;
}

function renderDashboard() {
  renderPersonalWelcomeCard();
  renderVisitCards();
  const total = members.length;
  const active = members.filter(m => m.status === 'Activo').length;
  const visits = countRecentVisitCards();
  const activePct = total > 0 ? Math.round((active / total) * 100) : 0;
  const activeMinistries = new Set(members.map(m => m.ministry).filter(m => m && m !== 'General')).size;

  document.getElementById('stat-total').textContent = total;
  document.getElementById('stat-active').textContent = active;
  document.getElementById('stat-visits').textContent = visits;
  document.getElementById('stat-active-pct').textContent = `${activePct}% del total`;
  document.getElementById('stat-ministries').textContent = activeMinistries;
  document.getElementById('stat-requests').textContent = prayerRequests.length;
}

function zoomImage(src) {
  if (!src) return;
  document.getElementById('zoomed-image').src = src;
  document.getElementById('image-zoom-modal').classList.remove('hidden');
}

function closeZoomModal() {
  document.getElementById('image-zoom-modal').classList.add('hidden');
}

function previewAvatar(event) {
  const file = event.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = function(e) {
      currentAvatarBase64 = e.target.result;
      const img = document.getElementById('avatar-preview-img');
      const initials = document.getElementById('avatar-preview-initials');
      img.src = currentAvatarBase64;
      img.classList.remove('hidden');
      initials.classList.add('hidden');
    };
    reader.readAsDataURL(file);
  }
}

function getBirthdayMembersForSelectedMonth() {
  const monthSelect = document.getElementById('share-birthday-month').value;
  const source = isMemberOnly() ? (memberBirthdayData || []) : members;
  return source.filter(m => {
    if (!m.birthday) return false;
    const parts = m.birthday.split('-');
    return parts.length >= 2 && parts[1] === monthSelect;
  });
}

function renderBirthdayModule() {
  const container = document.getElementById('birthday-module-list');
  const emptyState = document.getElementById('birthday-module-empty');
  const birthdayMembers = getBirthdayMembersForSelectedMonth();
  const monthSelect = document.getElementById('share-birthday-month').value;
  const monthNames = {
    "01": "enero", "02": "febrero", "03": "marzo", "04": "abril",
    "05": "mayo", "06": "junio", "07": "julio", "08": "agosto",
    "09": "septiembre", "10": "octubre", "11": "noviembre", "12": "diciembre"
  };

  container.innerHTML = '';

  if (birthdayMembers.length === 0) {
    emptyState.classList.remove('hidden');
    if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
    return;
  }

  emptyState.classList.add('hidden');

  // Agrupa las fechas en semanas de calendario de lunes a domingo.
  // La primera y última semana se recortan visualmente a los días del mes seleccionado.
  const year = new Date().getFullYear();
  const monthNumber = Number(monthSelect);
  const firstWeekday = (new Date(Date.UTC(year, monthNumber - 1, 1)).getUTCDay() + 6) % 7;
  const daysInMonth = new Date(Date.UTC(year, monthNumber, 0)).getUTCDate();
  const weeks = new Map();

  birthdayMembers
    .filter(member => member.birthday)
    .sort((a, b) => Number(a.birthday.split('-')[2]) - Number(b.birthday.split('-')[2]))
    .forEach(member => {
      const day = Number(member.birthday.split('-')[2]);
      if (!Number.isInteger(day) || day < 1 || day > daysInMonth) return;
      const weekIndex = Math.floor((day - 1 + firstWeekday) / 7);
      if (!weeks.has(weekIndex)) weeks.set(weekIndex, []);
      weeks.get(weekIndex).push(member);
    });

  weeks.forEach((weekMembers, weekIndex) => {
    const firstDay = Math.max(1, weekIndex * 7 - firstWeekday + 1);
    const lastDay = Math.min(daysInMonth, (weekIndex + 1) * 7 - firstWeekday);
    const weekSection = document.createElement('section');
    weekSection.className = 'space-y-3';

    const heading = document.createElement('div');
    heading.className = 'flex items-center gap-2 border-b border-slate-100 dark:border-slate-700 pb-2';
    heading.innerHTML = `
      <span class="inline-flex items-center justify-center w-7 h-7 rounded-lg bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">
        <i data-lucide="calendar-days" class="w-4 h-4"></i>
      </span>
      <div>
        <h4 class="text-sm font-bold text-slate-800 dark:text-white">Semana ${weekIndex + 1}</h4>
        <p class="text-[11px] text-slate-500 dark:text-slate-400">Lunes a domingo · ${firstDay} al ${lastDay} de ${monthNames[monthSelect]}</p>
      </div>
      <span class="ml-auto text-[11px] font-semibold text-amber-700 dark:text-amber-300">${weekMembers.length} ${weekMembers.length === 1 ? 'cumpleaños' : 'cumpleaños'}</span>
    `;

    const cardsGrid = document.createElement('div');
    cardsGrid.className = 'grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4';

    weekMembers.forEach(member => {
      const card = document.createElement('div');
      card.className = "min-w-0 min-h-[88px] bg-slate-50 dark:bg-slate-900/60 p-4 rounded-xl border border-slate-200 dark:border-slate-700/80 flex items-center justify-between gap-3 shadow-sm";

      const initials = member.name.split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase();
      let avatarHtml = `<div class="w-12 h-12 rounded-full bg-church-800 text-amber-300 font-bold flex items-center justify-center text-sm shrink-0">${escapeHtml(initials)}</div>`;
      if (member.avatar) {
        avatarHtml = `<div class="w-12 h-12 rounded-full overflow-hidden shrink-0 border-2 border-amber-400/50"><img src="${escapeHtml(member.avatar)}" class="w-full h-full object-cover" alt=""></div>`;
      }

      const parts = member.birthday.split('-');
      const birthYearText = parts.length === 3
        ? `🎂 ${parts[2]}/${parts[1]} (${parts[0]})`
        : '🎂 Fecha de cumpleaños';

      card.innerHTML = `
        <div class="flex min-w-0 flex-1 items-center gap-3">
          ${avatarHtml}
          <div class="min-w-0 flex-1">
            <p class="text-sm font-bold text-slate-800 dark:text-white whitespace-normal break-words leading-snug">${escapeHtml(member.name)}</p>
            <p class="mt-1 text-xs text-amber-600 dark:text-amber-400 font-semibold whitespace-normal">${escapeHtml(birthYearText)}</p>
          </div>
        </div>
      `;
      cardsGrid.appendChild(card);
    });

    weekSection.appendChild(heading);
    weekSection.appendChild(cardsGrid);
    container.appendChild(weekSection);
  });

  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

function getFilteredRequests() {
  const searchVal = document.getElementById('search-request-input').value.toLowerCase().trim();
  const timeFilter = document.getElementById('filter-request-time').value;
  const ownershipFilter = document.getElementById('filter-request-owner')?.value || 'all';
  const now = new Date();
  const oneDayMs = 24 * 60 * 60 * 1000;

  return prayerRequests.filter(req => {
    const member = members.find(m => m.id === req.memberId);
    const memberName = member ? member.name.toLowerCase() : '';
    const matchesSearch = req.text.toLowerCase().includes(searchVal) || memberName.includes(searchVal);

    let matchesTime = true;
    if (timeFilter === 'last-day') {
      const reqDate = new Date(req.createdAt);
      matchesTime = (now - reqDate) <= oneDayMs;
    }

    const matchesOwner = ownershipFilter !== 'mine' || (currentUser && currentUser.memberId && String(req.memberId) === String(currentUser.memberId));
    return matchesSearch && matchesTime && matchesOwner;
  });
}

function renderRequests() {
  const ownerFilter = document.getElementById('filter-request-owner');
  if (ownerFilter) {
    const memberCanFilterOwn = !!(currentUser && currentUser.memberId);
    ownerFilter.classList.toggle('hidden', !memberCanFilterOwn);
    if (!memberCanFilterOwn) ownerFilter.value = 'all';
  }
  const container = document.getElementById('requests-container');
  const emptyState = document.getElementById('requests-empty-state');
  const filtered = [...getFilteredRequests()];
  const sortMode = document.getElementById('sort-prayer-requests')?.value || 'newest';
  filtered.sort((a, b) => {
    if (sortMode === 'oldest') return new Date(a.createdAt) - new Date(b.createdAt);
    if (sortMode === 'name') {
      const nameA = (a.memberName || members.find(m => m.id === a.memberId)?.name || '').toLocaleLowerCase('es');
      const nameB = (b.memberName || members.find(m => m.id === b.memberId)?.name || '').toLocaleLowerCase('es');
      return nameA.localeCompare(nameB, 'es');
    }
    return new Date(b.createdAt) - new Date(a.createdAt);
  });
  const canEdit = currentUser && (hasRole("admin") || hasRole("pastor") || hasRole("lider") || hasServerMinistryPermissions());

  container.innerHTML = '';

  if (filtered.length === 0) {
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');

    filtered.forEach(req => {
      const member = members.find(m => m.id === req.memberId);
      const memberName = req.memberName || (member ? member.name : 'Hermano General');
      const reqDate = new Date(req.createdAt);
      const timeFormatted = reqDate.toLocaleDateString('es-CL') + ' · ' + reqDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      const card = document.createElement('article');
      card.className = "prayer-request-card bg-white dark:bg-slate-900/40 rounded-xl border border-slate-200 dark:border-slate-700/80 p-4 sm:p-5 shadow-sm flex flex-col gap-3";
      card.innerHTML = `
        <div class="flex items-start justify-between gap-3 border-b border-slate-100 dark:border-slate-700 pb-3">
          <div class="min-w-0">
            <span class="prayer-request-name block text-base font-bold text-amber-600 dark:text-amber-400">${escapeHtml(memberName)}</span>
            <span class="prayer-request-date mt-1 text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
              <i data-lucide="clock" class="w-3 h-3"></i> ${escapeHtml(timeFormatted)}
            </span>
          </div>
          ${canEdit ? `<button onclick="deleteRequest('${escapeHtml(req.id)}')" title="Eliminar petición" aria-label="Eliminar petición" class="shrink-0 p-2 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-900/20 transition"><i data-lucide="trash-2" class="w-4 h-4"></i></button>` : ''}
        </div>
        <p class="prayer-request-text text-sm leading-relaxed text-slate-700 dark:text-slate-200 whitespace-pre-wrap break-words">${escapeHtml(req.text)}</p>
      `;
      container.appendChild(card);
    });
  }

  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}


async function refreshPrayerRequests() {
  const button = document.getElementById("refresh-prayer-requests-button");
  const icon = document.getElementById("refresh-prayer-requests-icon");
  const label = document.getElementById("refresh-prayer-requests-label");
  if (!currentUser || !window.supabaseClient) return;

  if (button) button.disabled = true;
  if (icon) icon.classList.add("animate-spin");
  if (label) label.textContent = "Actualizando...";

  try {
    const { data, error } = await window.supabaseClient
      .from("peticiones_oracion")
      .select("*")
      .order("created_at", { ascending: false });
    if (error) throw error;

    prayerRequests = (data || []).map(mapDbRequestToApp);
    renderRequests();
  } catch (error) {
    console.error("No se pudieron actualizar las peticiones de oración:", error);
    alert("No fue posible actualizar las peticiones de oración. Revisa tu conexión e inténtalo nuevamente.");
  } finally {
    if (button) button.disabled = false;
    if (icon) icon.classList.remove("animate-spin");
    if (label) label.textContent = "Actualizar";
  }
}

function downloadFile(content, fileName, contentType) {
  const a = document.createElement("a");
  const file = new Blob([content], { type: contentType });
  a.href = URL.createObjectURL(file);
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(a.href);
}

let privateNoteContext = null;
async function loadAntecedentNotes(memberId) {
  const { data, error } = await window.supabaseClient.from("notas_antecedentes")
    .select("id,miembro_id,tipo,contenido,autor_id,autor_nombre,created_at")
    .eq("miembro_id", String(memberId))
    .order("created_at", { ascending: false });
  if (error) throw error;
  antecedentNotes = antecedentNotes.filter(note => String(note.miembro_id) !== String(memberId)).concat(data || []);
  renderAntecedentHistory(memberId, "pastoral");
  renderAntecedentHistory(memberId, "lider");
}

function renderAntecedentHistory(memberId, type) {
  const target = document.getElementById(type === "pastoral" ? "view-pastoral-history" : "view-leader-history");
  if (!target) return;
  target.innerHTML = "";
  const records = antecedentNotes.filter(note => String(note.miembro_id) === String(memberId) && note.tipo === type);
  if (!records.length) {
    const empty = document.createElement("p");
    empty.className = "text-xs text-slate-400 italic";
    empty.textContent = "Todavía no hay registros en esta sección.";
    target.appendChild(empty);
    return;
  }
  records.forEach(note => {
    const card = document.createElement("article");
    card.className = "rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/70 p-3 space-y-2";
    const body = document.createElement("p");
    body.className = "text-sm text-slate-700 dark:text-slate-200 whitespace-pre-wrap break-words";
    body.textContent = note.contenido;
    const meta = document.createElement("p");
    meta.className = "text-[11px] text-slate-500 dark:text-slate-400";
    const date = note.created_at ? new Date(note.created_at).toLocaleString("es-CL", { dateStyle: "medium", timeStyle: "short" }) : "Fecha no disponible";
    meta.textContent = "Registrado por " + (note.autor_nombre || "Usuario") + " · " + date;
    card.append(body, meta);
    target.appendChild(card);
  });
}

async function openPrivateNoteModal(memberId, type) {
  const member = members.find(item => String(item.id) === String(memberId));
  if (!member || !currentUser) return;
  if (type === "pastoral" && !(hasRole("admin") || hasRole("pastor"))) return;
  if (type === "leader" && !hasRole("lider")) return;
  privateNoteContext = { memberId: String(memberId), type };
  document.getElementById("private-note-title").textContent = type === "pastoral" ? "Nuevo antecedente pastoral" : "Nuevo antecedente de líder";
  document.getElementById("private-note-member").textContent = member.name;
  const field = document.getElementById("private-note-text");
  field.value = "";
  field.placeholder = "Escribe el nuevo comentario. Se guardará con tu nombre y fecha.";
  document.getElementById("private-note-modal").classList.remove("hidden");
}
function closePrivateNoteModal() {
  document.getElementById("private-note-modal").classList.add("hidden");
  privateNoteContext = null;
}
async function savePrivateNote(event) {
  event.preventDefault();
  if (!privateNoteContext || !currentUser) return;
  const note = document.getElementById("private-note-text").value.trim();
  if (!note) { alert("Escribe un comentario antes de guardar."); return; }
  const type = privateNoteContext.type === "pastoral" ? "pastoral" : "lider";
  if (type === "pastoral" && !(hasRole("admin") || hasRole("pastor"))) return;
  if (type === "lider" && !hasRole("lider")) return;
  const memberId = privateNoteContext.memberId;
  const { error } = await window.supabaseClient.from("notas_antecedentes").insert({
    miembro_id: memberId, tipo: type, contenido: note
  });
  if (error) { alert("No se pudo guardar el antecedente: " + error.message); return; }
  closePrivateNoteModal();
  try {
    await loadAntecedentNotes(memberId);
    alert("Comentario guardado con tu nombre y fecha/hora.");
  } catch (refreshError) {
    console.error(refreshError);
    alert("El comentario se guardó, pero no se pudo actualizar el historial. Vuelve a abrir la ficha.");
  }
}

function renderTable() {
  const tbody = document.getElementById('members-table-body');
  const emptyState = document.getElementById('empty-state');
  if (!tbody) return;

  const searchVal = document.getElementById('search-input').value.toLowerCase().trim();
  const maritalFilter = document.getElementById('filter-marital-status').value;
  const ministryFilter = document.getElementById('filter-ministry').value;
  const statusFilter = document.getElementById('filter-status').value;

  const serverRestricted = currentUser && hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor");
  const canEdit = currentUser && !serverRestricted && (hasRole("admin") || hasRole("pastor"));
  const canAddPastoralNote = currentUser && (hasRole("admin") || hasRole("pastor"));
  const canAddLeaderNote = currentUser && hasRole("lider");

  tbody.innerHTML = '';

  const roleScopedMembers = rolePreviewActive && hasRole("lider")
    ? members.filter(member => member.ministry === currentUser.ministry)
    : rolePreviewActive && isMemberOnly()
      ? members.filter(member => String(member.id) === String(currentUser.memberId))
      : members;
  const filtered = roleScopedMembers.filter(m => {
    const matchesSearch = 
      m.name.toLowerCase().includes(searchVal) || 
      m.phone.toLowerCase().includes(searchVal) || 
      (m.email && m.email.toLowerCase().includes(searchVal));
    
    const matchesMarital = maritalFilter === '' || m.maritalStatus === maritalFilter;
    const matchesMinistry = ministryFilter === '' || m.ministry === ministryFilter;
    const matchesStatus = statusFilter === '' || m.status === statusFilter;

    return matchesSearch && matchesMarital && matchesMinistry && matchesStatus;
  });

  if (filtered.length === 0) {
    if (emptyState) emptyState.classList.remove('hidden');
  } else {
    if (emptyState) emptyState.classList.add('hidden');

    filtered.forEach(m => {
      const tr = document.createElement('tr');
      tr.className = "hover:bg-slate-50 dark:hover:bg-slate-700/50 transition border-b border-slate-100 dark:border-slate-700";

      let statusBadgeClass = "bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-600";
      if (m.status === 'Activo') statusBadgeClass = "bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800";
      if (m.status === 'En Visita') statusBadgeClass = "bg-amber-50 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800";
      if (m.status === 'Inactivo') statusBadgeClass = "bg-rose-50 dark:bg-rose-900/30 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800";

      const initials = m.name.split(' ').map(n => n[0]).slice(0,2).join('').toUpperCase();

      let avatarHtml = `<div class="w-9 h-9 rounded-full bg-church-800 text-amber-300 font-bold flex items-center justify-center text-xs shrink-0">${escapeHtml(initials)}</div>`;
      if (m.avatar) {
        avatarHtml = `<div class="w-9 h-9 rounded-full overflow-hidden shrink-0 border border-amber-400/40 cursor-pointer hover:opacity-80 transition" onclick="zoomImage('${escapeHtml(m.avatar)}')" title="Ver foto ampliada"><img src="${escapeHtml(m.avatar)}" class="w-full h-full object-cover" alt="Foto"></div>`;
      }

      tr.innerHTML = `
        <td class="py-3 px-4">
          <div class="flex items-center gap-3">
            ${avatarHtml}
            <div>
              <p class="font-semibold text-slate-900 dark:text-white">${escapeHtml(m.name)}</p>
              <p class="text-xs text-slate-500 dark:text-slate-400">${escapeHtml(m.phone)} ${m.email ? '• ' + escapeHtml(m.email) : ''}</p>
            </div>
          </div>
        </td>
        <td class="py-3 px-4">
          <span class="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
            ${escapeHtml(m.ministry || 'General')}
          </span>
        </td>
        <td class="py-3 px-4 text-xs font-medium text-slate-700 dark:text-slate-300">
          ${escapeHtml(m.maritalStatus || 'Soltero (a)')}
        </td>
        <td class="py-3 px-4">
          <span class="text-xs font-medium ${m.baptized === 'Sí' ? 'text-blue-600 dark:text-blue-400' : 'text-slate-400 dark:text-slate-500'}">
            ${m.baptized === 'Sí' ? '✓ Bautizado' : 'Pendiente'}
          </span>
        </td>
        <td class="py-3 px-4">
          <span class="inline-block px-2.5 py-0.5 rounded-full text-xs font-semibold border ${statusBadgeClass}">
            ${escapeHtml(m.status)}
          </span>
        </td>
        <td class="py-3 px-4 text-xs text-slate-500 dark:text-slate-400">
          ${m.birthday ? escapeHtml(formatDate(m.birthday)) : 'N/A'}
        </td>
        <td class="py-3 px-4 text-right">
          <div class="flex items-center justify-end gap-1">
            <button onclick="viewDetails('${escapeHtml(m.id)}')" title="Ver Detalle" class="p-1.5 text-slate-500 dark:text-slate-400 hover:text-church-800 dark:hover:text-amber-400 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition">
              <i data-lucide="eye" class="w-4 h-4"></i>
            </button>
            ${canAddPastoralNote ? '<button data-member-id="' + escapeHtml(m.id) + '" data-note-type="pastoral" onclick="openPrivateNoteModal(this.dataset.memberId,this.dataset.noteType)" title="Nota pastoral" class="p-1.5 text-violet-600 hover:bg-violet-50 dark:hover:bg-slate-700 rounded-lg"><i data-lucide="notebook-pen" class="w-4 h-4"></i></button>' : ''}
            ${canAddLeaderNote ? '<button data-member-id="' + escapeHtml(m.id) + '" data-note-type="leader" onclick="openPrivateNoteModal(this.dataset.memberId,this.dataset.noteType)" title="Mi nota de líder" class="p-1.5 text-amber-600 hover:bg-amber-50 dark:hover:bg-slate-700 rounded-lg"><i data-lucide="notebook-pen" class="w-4 h-4"></i></button>' : ''}
            ${canEdit ? `
            <button onclick="editMember('${escapeHtml(m.id)}')" title="Editar Miembro" class="p-1.5 text-slate-500 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition">
              <i data-lucide="edit-3" class="w-4 h-4"></i>
            </button>
            <button onclick="deleteMember('${escapeHtml(m.id)}')" title="Eliminar" class="p-1.5 text-slate-500 dark:text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition">
              <i data-lucide="trash-2" class="w-4 h-4"></i>
            </button>` : ''}
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

function handleMaritalStatusChange() {
  const status = document.getElementById('input-marital-status').value;
  const spouseSection = document.getElementById('spouse-section');
  const spouseLabel = document.getElementById('spouse-section-label');
  
  if (status === 'Casado (a)' || status === 'Novio (a)') {
    spouseSection.classList.remove('hidden');
    spouseLabel.textContent = status === 'Casado (a)' ? 'Información del Cónyuge' : 'Información del Novio / Novia';
    populateSpouseSelect();
  } else {
    spouseSection.classList.add('hidden');
  }
}

function toggleSpouseInputType() {
  const selectedType = document.querySelector('input[name="spouse_type"]:checked').value;
  const selectContainer = document.getElementById('spouse-select-container');
  const textContainer = document.getElementById('spouse-text-container');

  if (selectedType === 'link') {
    selectContainer.classList.remove('hidden');
    textContainer.classList.add('hidden');
  } else {
    selectContainer.classList.add('hidden');
    textContainer.classList.remove('hidden');
  }
}

function populateSpouseSelect(currentMemberId = '') {
  const select = document.getElementById('input-spouse-id');
  select.innerHTML = '<option value="">-- Seleccionar Hermano(a) --</option>';
  
  members.forEach(m => {
    if (m.id !== currentMemberId) {
      const opt = document.createElement('option');
      opt.value = m.id;
      opt.textContent = m.name;
      select.appendChild(opt);
    }
  });
}

function populateInviterSelect(currentMemberId = "") {
  const select = document.getElementById("input-inviter-member");
  if (!select) return;
  select.innerHTML = '<option value="">-- Seleccionar del directorio --</option>';
  members
    .filter(member => String(member.id) !== String(currentMemberId))
    .sort((a, b) => (a.name || "").localeCompare(b.name || "", "es"))
    .forEach(member => {
      const option = document.createElement("option");
      option.value = String(member.id);
      option.textContent = member.name;
      select.appendChild(option);
    });
  const manual = document.createElement("option");
  manual.value = "__manual__";
  manual.textContent = "No aparece en el directorio / Escribir nombre";
  select.appendChild(manual);
}

function toggleInviterManualField() {
  const select = document.getElementById("input-inviter-member");
  const container = document.getElementById("inviter-manual-container");
  const name = document.getElementById("input-inviter-name");
  if (!select || !container) return;
  const manual = select.value === "__manual__";
  container.classList.toggle("hidden", !manual);
  if (!manual && name) name.value = "";
}

function toggleVisitInvitationFields() {
  const status = document.getElementById("input-status");
  const section = document.getElementById("visit-invitation-section");
  if (!status || !section) return;
  section.classList.toggle("hidden", status.value !== "En Visita");
  if (status.value === "Activo") {
    const select = document.getElementById("input-inviter-member");
    const name = document.getElementById("input-inviter-name");
    const relationship = document.getElementById("input-inviter-relationship");
    if (select) select.value = "";
    if (name) name.value = "";
    if (relationship) relationship.value = "";
    toggleInviterManualField();
  }
}

function openModal(isEdit = false) {
  if (!currentUser || !(hasRole("admin") || hasRole("pastor") || hasServerMinistryPermissions()) || (isEdit && hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor"))) return;
  const modal = document.getElementById('member-modal');
  const title = document.getElementById('modal-title');
  
  if (!isEdit) {
    document.getElementById('member-form').reset();
    document.getElementById('member-id').value = '';
    populateInviterSelect("");
    document.getElementById("input-inviter-member").value = "";
    document.getElementById("input-inviter-name").value = "";
    document.getElementById("input-inviter-relationship").value = "";
    toggleInviterManualField();
    document.getElementById('input-birthday').value = new Date().toISOString().split('T')[0];
    document.getElementById('input-marital-status').value = 'Soltero (a)';
    currentAvatarBase64 = "";
    
    document.getElementById('avatar-preview-img').classList.add('hidden');
    document.getElementById('avatar-preview-initials').classList.remove('hidden');
    document.getElementById('avatar-preview-initials').textContent = '--';

    handleMaritalStatusChange();
    const restrictedServer = hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor");
    const statusInput = document.getElementById("input-status");
    if (statusInput) {
      statusInput.disabled = restrictedServer;
      statusInput.value = restrictedServer ? "En Visita" : "Activo";
    }
    const serverHint = document.getElementById("server-visit-only-hint");
    if (serverHint) serverHint.classList.toggle("hidden", !restrictedServer);
    toggleVisitInvitationFields();
    title.textContent = 'Agregar Nuevo Hermano';
  } else {
    title.textContent = 'Editar Información del Hermano';
  }
  modal.classList.remove('hidden');
}

function closeModal() {
  document.getElementById('member-modal').classList.add('hidden');
}

let requestSelectedMemberId = null;
let requestSearchTimer = null;
let requestSearchSequence = 0;

function openRequestModal() {
  if (!currentUser) return;
  document.getElementById("request-form").reset();
  const nameInput = document.getElementById("request-member-name");
  nameInput.value = currentUser.name || "";
  requestSelectedMemberId = currentUser.memberId || null;
  const results = document.getElementById("request-member-results");
  if (results) { results.innerHTML = ""; results.classList.add("hidden"); }
  document.getElementById('request-modal').classList.remove('hidden');
  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

async function searchRequestMembers() {
  const input = document.getElementById("request-member-name");
  const results = document.getElementById("request-member-results");
  if (!input || !results) return;
  requestSelectedMemberId = null;
  const term = input.value.trim();
  const sequence = ++requestSearchSequence;
  if (requestSearchTimer) clearTimeout(requestSearchTimer);
  if (term.length < 2) {
    results.innerHTML = "";
    results.classList.add("hidden");
    return;
  }
  results.innerHTML = '<div class="px-3 py-2 text-xs text-slate-500">Buscando miembros...</div>';
  results.classList.remove("hidden");
  requestSearchTimer = setTimeout(async () => {
    try {
      const { data, error } = await window.supabaseClient.rpc("buscar_miembros_para_peticion", { p_busqueda: term });
      if (sequence !== requestSearchSequence) return;
      if (error) throw error;
      results.innerHTML = "";
      if (!data || !data.length) {
        results.innerHTML = '<div class="px-3 py-2 text-xs text-slate-500">No se encontró una ficha. La petición quedará sin asociar.</div>';
        return;
      }
      data.forEach(member => {
        const option = document.createElement("button");
        option.type = "button";
        option.className = "w-full text-left px-3 py-2 hover:bg-amber-50 dark:hover:bg-slate-700 flex items-center justify-between gap-3";
        const name = document.createElement("span");
        name.className = "text-sm font-medium text-slate-800 dark:text-slate-100";
        name.textContent = member.name;
        const status = document.createElement("span");
        status.className = "text-xs text-slate-500 dark:text-slate-400 shrink-0";
        status.textContent = member.status || "Ficha";
        option.append(name, status);
        option.addEventListener("click", () => selectRequestMember(member.id, member.name));
        results.appendChild(option);
      });
    } catch (error) {
      console.error("Error buscando miembros para petición:", error);
      if (sequence === requestSearchSequence) {
        results.innerHTML = '<div class="px-3 py-2 text-xs text-rose-600">No fue posible buscar en la base de datos.</div>';
      }
    }
  }, 250);
}

function selectRequestMember(memberId, memberName) {
  requestSelectedMemberId = memberId;
  document.getElementById("request-member-name").value = memberName;
  const results = document.getElementById("request-member-results");
  if (results) { results.innerHTML = ""; results.classList.add("hidden"); }
}

function closeRequestModal() {
  document.getElementById('request-modal').classList.add('hidden');
}

async function handleRequestSubmit(e) {
  e.preventDefault();
  if (!currentUser) return;

  const memberName = document.getElementById("request-member-name").value.trim();
  const memberId = requestSelectedMemberId || null;
  if (!memberName) {
    alert("Escribe el nombre de quien solicita la oración.");
    return;
  }
  const text = document.getElementById("request-description").value.trim();
  if (!text) {
    alert("Escribe el motivo de oración antes de guardar.");
    return;
  }

  const newReq = {
    id: "r_" + Date.now(),
    memberId: memberId,
    memberName: memberName,
    text: text,
    createdAt: new Date().toISOString()
  };

  try {
    // INSERT directo: permite registrar peticiones propias sin conceder edición de registros existentes.
    const { data, error } = await window.supabaseClient
      .from("peticiones_oracion")
      .insert({
        id: newReq.id,
        member_id: newReq.memberId || null,
        member_name: newReq.memberName,
        description: newReq.text,
        created_at: newReq.createdAt,
        created_by: currentUser.id
      })
.select("id,member_id,member_name,description,created_at,created_by")
      .single();

    if (error) throw error;

    prayerRequests.unshift(mapDbRequestToApp(data));
    renderDashboard();
    renderRequests();
    closeRequestModal();
    document.getElementById("request-form").reset();
  } catch (error) {
    console.error(error);
    alert("No se pudo guardar la petición: " + error.message);
  }
}

async function deleteRequest(id) {
  if (!currentUser || !(hasRole("admin") || hasRole("pastor") || hasServerMinistryPermissions())) return;
  if (!confirm("¿Estás seguro de eliminar esta petición de oración?")) return;

  const { error } = await window.supabaseClient
    .from("peticiones_oracion")
    .delete()
    .eq("id", id);

  if (error) {
    alert("No se pudo eliminar la petición: " + error.message);
    return;
  }

  prayerRequests = prayerRequests.filter(request => request.id !== id);
  renderDashboard();
  renderRequests();
}

async function handleFormSubmit(e) {
  e.preventDefault();
  if (!currentUser || !(hasRole("admin") || hasRole("pastor") || hasServerMinistryPermissions())) return;

  const id = document.getElementById("member-id").value;
  if (id && hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor")) {
    alert("El ministerio Servidores solo puede crear fichas de visitas, no editar registros existentes.");
    return;
  }
  const currentMemberId = id || Date.now().toString();
  const name = document.getElementById("input-name").value.trim();
  const maritalStatus = document.getElementById("input-marital-status").value;

  let spouseType = "none";
  let spouseName = "";
  let spouseId = "";

  if (maritalStatus === "Casado (a)" || maritalStatus === "Novio (a)") {
    const selectedType = document.querySelector('input[name="spouse_type"]:checked');
    spouseType = selectedType ? selectedType.value : "none";

    if (spouseType === "link") {
      spouseId = document.getElementById("input-spouse-id").value;
      const foundSpouse = members.find(member => member.id === spouseId);
      spouseName = foundSpouse ? foundSpouse.name : "";
    } else {
      spouseName = document.getElementById("input-spouse-name").value.trim();
    }
  }

  const oldMember = members.find(member => member.id === currentMemberId);
  if (oldMember && oldMember.spouseId && oldMember.spouseId !== spouseId) {
    const oldSpouse = members.find(member => member.id === oldMember.spouseId);
    if (oldSpouse && oldSpouse.spouseId === currentMemberId) {
      oldSpouse.spouseId = "";
      oldSpouse.spouseName = "";
      oldSpouse.spouseType = "none";
    }
  }

  let avatarToSave = currentAvatarBase64;
  if (!avatarToSave && oldMember) avatarToSave = oldMember.avatar || "";

  const memberData = {
    id: currentMemberId,
    name: name,
    phone: document.getElementById("input-phone").value.trim(),
    email: document.getElementById("input-email").value.trim(),
    address: document.getElementById("input-address").value.trim(),
    maritalStatus: maritalStatus,
    spouseType: spouseType,
    spouseName: spouseName,
    spouseId: spouseId,
    ministry: document.getElementById("input-ministry").value,
    status: (hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor"))
      ? "En Visita"
      : document.getElementById("input-status").value,
    inviterMemberId: document.getElementById("input-status").value !== "Activo" &&
      document.getElementById("input-inviter-member").value !== "__manual__"
      ? document.getElementById("input-inviter-member").value : "",
    inviterName: document.getElementById("input-status").value !== "Activo"
      ? (document.getElementById("input-inviter-member").value === "__manual__"
        ? document.getElementById("input-inviter-name").value.trim()
        : (members.find(member => String(member.id) === document.getElementById("input-inviter-member").value)?.name || ""))
      : "",
    inviterRelationship: document.getElementById("input-status").value !== "Activo"
      ? document.getElementById("input-inviter-relationship").value.trim() : "",
    baptized: document.getElementById("input-baptized").value,
    birthday: document.getElementById("input-birthday").value || "",
    notes: document.getElementById("input-notes").value.trim(),
    avatar: avatarToSave,
    createdAt: oldMember?.createdAt || new Date().toISOString()
  };

  const serverOnly = hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor");
  if (!serverOnly) {
    if (id) {
      const index = members.findIndex(member => member.id === id);
      if (index !== -1) members[index] = memberData;
    } else {
      members.unshift(memberData);
    }
  }

  if ((maritalStatus === "Casado (a)" || maritalStatus === "Novio (a)") &&
      spouseType === "link" && spouseId) {
    const targetSpouse = members.find(member => member.id === spouseId);
    if (targetSpouse) {
      targetSpouse.maritalStatus = maritalStatus;
      targetSpouse.spouseType = "link";
      targetSpouse.spouseId = currentMemberId;
      targetSpouse.spouseName = name;
    }
  }

  try {
    if (hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor")) {
      const { error } = await window.supabaseClient.from("miembros_app").insert(mapAppMemberToDb(memberData));
      if (error) throw error;
      visitCards.unshift({
        id: memberData.id,
        name: memberData.name,
        status: "En Visita",
        createdAt: memberData.createdAt,
        inviterName: memberData.inviterName,
        inviterRelationship: memberData.inviterRelationship
      });
    } else {
      await saveMembers();
    }
    renderDashboard();
    renderTable();
    renderBirthdayModule();
    closeModal();
  } catch (error) {
    console.error(error);
    alert("No se pudo guardar el miembro en Supabase: " + error.message);
    try {
      await refreshCloudData();
      renderDashboard();
      renderTable();
      renderBirthdayModule();
    } catch (_) {}
  }
}

function editMember(id) {
  const serverRestricted = hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor");
  if (!currentUser || serverRestricted || !(hasRole("admin") || hasRole("pastor"))) return;
  const member = members.find(m => m.id === id);
  if (!member) return;

  document.getElementById('member-id').value = member.id;
  document.getElementById('input-name').value = member.name;
  document.getElementById('input-phone').value = member.phone;
  document.getElementById('input-email').value = member.email || '';
  document.getElementById('input-address').value = member.address || '';
  document.getElementById('input-marital-status').value = member.maritalStatus || 'Soltero (a)';
  
  currentAvatarBase64 = member.avatar || '';
  const previewImg = document.getElementById('avatar-preview-img');
  const previewInitials = document.getElementById('avatar-preview-initials');
  
  if (currentAvatarBase64) {
    previewImg.src = currentAvatarBase64;
    previewImg.classList.remove('hidden');
    previewInitials.classList.add('hidden');
  } else {
    previewImg.classList.add('hidden');
    previewInitials.classList.remove('hidden');
    previewInitials.textContent = member.name.split(' ').map(n => n[0]).slice(0,2).join('').toUpperCase();
  }

  handleMaritalStatusChange();
  populateSpouseSelect(member.id);

  if (member.maritalStatus === 'Casado (a)' || member.maritalStatus === 'Novio (a)') {
    const spouseType = member.spouseType || 'link';
    const radio = document.querySelector(`input[name="spouse_type"][value="${spouseType}"]`);
    if (radio) radio.checked = true;
    
    toggleSpouseInputType();

    if (spouseType === 'link') {
      document.getElementById('input-spouse-id').value = member.spouseId || '';
    } else {
      document.getElementById('input-spouse-name').value = member.spouseName || '';
    }
  }

  document.getElementById('input-ministry').value = member.ministry || 'General';
  document.getElementById('input-status').value = member.status || 'Activo';
  document.getElementById('input-baptized').value = member.baptized || 'Sí';
  document.getElementById('input-birthday').value = member.birthday || '';
  document.getElementById('input-notes').value = member.notes || '';

  openModal(true);
  populateInviterSelect(member.id);
  if (member.inviterMemberId) {
    document.getElementById("input-inviter-member").value = String(member.inviterMemberId);
  } else if (member.inviterName) {
    document.getElementById("input-inviter-member").value = "__manual__";
    document.getElementById("input-inviter-name").value = member.inviterName;
  }
  document.getElementById("input-inviter-relationship").value = member.inviterRelationship || "";
  toggleInviterManualField();
  toggleVisitInvitationFields();
}

async function deleteMember(id) {
  const serverRestricted = hasServerMinistryPermissions() && !hasRole("admin") && !hasRole("pastor");
  if (!currentUser || serverRestricted || !(hasRole("admin") || hasRole("pastor") || hasRole("lider"))) return;

  const member = members.find(item => item.id === id);
  if (!member) return;

  if (!confirm("¿Está seguro de eliminar a " + member.name + " de los registros?")) return;

  const { error } = await window.supabaseClient
    .from("miembros_app")
    .delete()
    .eq("id", id);

  if (error) {
    alert("No se pudo eliminar el miembro: " + error.message);
    return;
  }

  if (member.spouseId) {
    const partner = members.find(item => item.id === member.spouseId);
    if (partner && partner.spouseId === id) {
      partner.spouseId = "";
      partner.spouseName = "";
      partner.spouseType = "none";
    }
  }

  members = members.filter(item => item.id !== id);

  try {
    await saveMembers();
    renderDashboard();
    renderTable();
    renderBirthdayModule();
  } catch (saveError) {
    console.error(saveError);
    alert("El miembro fue eliminado, pero no se pudo actualizar el vínculo familiar: " + saveError.message);
    await refreshCloudData();
    renderDashboard();
    renderTable();
    renderBirthdayModule();
  }
}

function viewDetails(id) {
  const member = members.find(m => m.id === id);
  window.currentDetailsMemberId = member ? member.id : null;
  if (!member) return;

  const initials = member.name.split(' ').map(n => n[0]).slice(0,2).join('').toUpperCase();
  const viewImg = document.getElementById('view-avatar-img');
  const viewInitials = document.getElementById('view-avatar-initials');

  if (member.avatar) {
    viewImg.src = member.avatar;
    viewImg.classList.remove('hidden');
    viewInitials.classList.add('hidden');
  } else {
    viewImg.classList.add('hidden');
    viewInitials.classList.remove('hidden');
    viewInitials.textContent = initials;
  }

  document.getElementById('view-name').textContent = member.name;
  
  const badge = document.getElementById('view-status-badge');
  badge.textContent = member.status;
  badge.className = `inline-block px-2.5 py-0.5 rounded-full text-xs font-semibold ${
    member.status === 'Activo' ? 'bg-emerald-100 text-emerald-800' :
    member.status === 'En Visita' ? 'bg-amber-100 text-amber-800' : 'bg-rose-100 text-rose-800'
  }`;

  document.getElementById('view-phone').textContent = member.phone || 'No registrado';
  document.getElementById('view-email').textContent = member.email || 'No registrado';
  document.getElementById('view-marital-status').textContent = member.maritalStatus || 'Soltero (a)';
  
  let spouseDisplay = 'N/A';
  if (member.maritalStatus === 'Casado (a)' || member.maritalStatus === 'Novio (a)') {
    if (member.spouseType === 'link' && member.spouseId) {
      const spouseObj = members.find(m => m.id === member.spouseId);
      spouseDisplay = spouseObj ? spouseObj.name : (member.spouseName || 'Hermano registrado');
    } else {
      spouseDisplay = member.spouseName || 'No especificado';
    }
  }

  document.getElementById('view-spouse-label').textContent = member.maritalStatus === 'Casado (a)' ? 'Cónyuge' : 'Pareja / Novio(a)';
  document.getElementById('view-spouse').textContent = spouseDisplay;

  document.getElementById('view-ministry').textContent = member.ministry || 'General';
  document.getElementById('view-baptized').textContent = member.baptized;
  document.getElementById('view-address').textContent = member.address || 'Sin dirección';
  document.getElementById('view-date').textContent = member.birthday ? formatDate(member.birthday) : 'N/A';
  const pastoralHistory = document.getElementById("view-pastoral-history-section");
  const leaderHistory = document.getElementById("view-leader-history-section");
  const canPastoral = hasRole("admin") || hasRole("pastor");
  const canLeader = canPastoral || hasRole("lider");
  if (pastoralHistory) pastoralHistory.classList.toggle("hidden", !canPastoral);
  if (leaderHistory) leaderHistory.classList.toggle("hidden", !canLeader);
  const addPastoral = document.getElementById("add-pastoral-note-button");
  const addLeader = document.getElementById("add-leader-note-button");
  if (addPastoral) addPastoral.classList.toggle("hidden", !canPastoral);
  if (addLeader) addLeader.classList.toggle("hidden", !hasRole("lider"));
  loadAntecedentNotes(member.id).catch(error => console.error("No se pudo cargar el historial:", error));
  const ownPhotoControls = document.getElementById("view-own-photo-controls");
  if (ownPhotoControls) ownPhotoControls.classList.toggle("hidden", !(currentUser && currentUser.memberId && String(currentUser.memberId) === String(member.id)));
  const ministryControls = document.getElementById("view-ministry-management");
  if (ministryControls) {
    const ownMember = currentUser && currentUser.memberId
      ? members.find(m => String(m.id) === String(currentUser.memberId)) : null;
    const ownMinistry = ownMember ? (ownMember.ministry || "General") : "";
    const isAdmin = hasRole("admin");
    const canLeaderRemove = hasRole("lider") && ownMinistry !== "General" &&
      (member.ministry || "General") === ownMinistry && String(member.id) !== String(currentUser.memberId);
    ministryControls.classList.toggle("hidden", !(isAdmin || canLeaderRemove));
    const adminControls = document.getElementById("view-admin-ministry-controls");
    const leaderControls = document.getElementById("view-leader-ministry-controls");
    if (adminControls) adminControls.classList.toggle("hidden", !isAdmin);
    if (leaderControls) leaderControls.classList.toggle("hidden", !canLeaderRemove);
    const ministrySelect = document.getElementById("view-admin-ministry-select");
    if (ministrySelect) ministrySelect.value = member.ministry || "General";
  }
  const accessControls = document.getElementById("view-admin-access-controls");
  if (accessControls) {
    const linkedAccount = users.find(user => String(user.memberId) === String(member.id));
    accessControls.classList.toggle("hidden", !(currentUser && hasRole("admin")));
    const accessButton = document.getElementById("view-create-access-button");
    const accessStatus = document.getElementById("view-admin-access-status");
    if (accessButton) {
      accessButton.disabled = member.status !== "Activo" || !String(member.email || "").trim();
      accessButton.textContent = linkedAccount ? "Reenviar enlace de contraseña" : "Crear acceso a Renacer";
    }
    if (accessStatus) {
      accessStatus.textContent = linkedAccount
        ? "Acceso vinculado a " + linkedAccount.username + ". Puedes reenviar el enlace para establecer una nueva contraseña."
        : (member.status !== "Activo" ? "La ficha debe estar Activa para habilitar el acceso." : (!member.email ? "Registra un correo electrónico para continuar." : "Esta ficha todavía no tiene una cuenta de acceso."));
    }
  }

  document.getElementById('details-modal').classList.remove('hidden');
  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}


async function changeOwnProfilePhoto(event) {
  const file = event.target.files && event.target.files[0];
  event.target.value = "";
  if (!file || !currentUser || !currentUser.memberId) return;
  if (!file.type.startsWith("image/") || file.size > 2 * 1024 * 1024) { alert("Selecciona una imagen de máximo 2 MB."); return; }
  const button = document.getElementById("view-change-photo-button");
  if (button) { button.disabled = true; button.textContent = "Guardando foto..."; }
  try {
    const ext = (file.name.split(".").pop() || "jpg").toLowerCase().replace(/[^a-z0-9]/g, "") || "jpg";
    const path = "users/" + currentUser.id + "/" + crypto.randomUUID() + "." + ext;
    const { error: uploadError } = await window.supabaseClient.storage.from("profile-photos").upload(path, file, { contentType: file.type, upsert: false });
    if (uploadError) throw uploadError;
    const url = window.supabaseClient.storage.from("profile-photos").getPublicUrl(path).data.publicUrl;
    const { error } = await window.supabaseClient.rpc("actualizar_mi_foto", { p_avatar_url: url });
    if (error) throw error;
    const member = members.find(item => String(item.id) === String(currentUser.memberId));
    if (member) member.avatar = url;
    renderPersonalWelcomeCard();
    if (member) viewDetails(member.id);
    alert("Tu foto de perfil se actualizó correctamente.");
  } catch (error) {
    console.error("Error actualizando foto:", error);
    alert("No se pudo actualizar la foto: " + error.message);
  } finally {
    if (button) { button.disabled = false; button.textContent = "Cambiar mi foto"; }
  }
}

function closeDetailsModal() {
  document.getElementById('details-modal').classList.add('hidden');
}

function resetFilters() {
  document.getElementById('search-input').value = '';
  document.getElementById('filter-marital-status').value = '';
  document.getElementById('filter-ministry').value = '';
  document.getElementById('filter-status').value = '';
  renderTable();
}

function updateThemeIcons(isDark) {
  const darkIcon = document.getElementById('theme-toggle-dark-icon');
  const lightIcon = document.getElementById('theme-toggle-light-icon');
  if (isDark) {
    darkIcon.classList.add('hidden');
    lightIcon.classList.remove('hidden');
  } else {
    lightIcon.classList.add('hidden');
    darkIcon.classList.remove('hidden');
  }
}

function initTheme() {
  const savedTheme = localStorage.getItem('theme');
  const isDark = savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches);
  if (isDark) {
    document.documentElement.classList.add('dark');
  } else {
    document.documentElement.classList.remove('dark');
  }
  updateThemeIcons(isDark);
}

function toggleDarkMode() {
  const isDark = document.documentElement.classList.contains('dark');
  if (isDark) {
    document.documentElement.classList.remove('dark');
    localStorage.setItem('theme', 'light');
    updateThemeIcons(false);
  } else {
    document.documentElement.classList.add('dark');
    localStorage.setItem('theme', 'dark');
    updateThemeIcons(true);
  }
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  const parts = dateStr.split('-');
  if (parts.length === 3) {
    return `${parts[2]}/${parts[1]}`;
  }
  return dateStr;
}

// Inicializar la aplicación una sola vez.
document.addEventListener("DOMContentLoaded", function() {
  initTheme();
  loadData();
  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
});
