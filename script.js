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
function hasRole(role) {
  return !!(currentUser && Array.isArray(currentUser.roles) && currentUser.roles.includes(role));
}
function roleDisplayName(role) {
  return ({ hermano: "Miembro", admin: "Administrador", pastor: "Pastor", servidor: "Servidor", lider: "Líder" })[role] || role;
}
function isMemberOnly() { return !!(currentUser && hasRole("miembro") && !hasRole("admin") && !hasRole("pastor")); }
let members = [];
let prayerRequests = [];
let announcements = [];
let currentAvatarBase64 = "";

let realtimeChannel = null;
let realtimeRefreshTimer = null;

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
    avatar: row.avatar || ""
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
    avatar: member.avatar || null,
    updated_at: new Date().toISOString()
  };
}

function mapDbRequestToApp(row) {
  return {
    id: row.id,
    memberId: row.member_id || "",
    memberName: row.member_name || "",
    text: row.description || "",
    createdAt: row.created_at
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

  members = (membersResult.data || []).map(row => ({
    ...mapDbMemberToApp(row),
    notes: privateNotes.get(row.id) || "",
    leaderNotes: (leaderNotes.get(row.id) || []).join("\n\n")
  }));
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
  lucide.createIcons();
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
  const address = document.getElementById("public-member-address").value.trim();
  const maritalStatus = document.getElementById("public-member-marital").value;
  const spouseName = (maritalStatus === "Casado (a)" || maritalStatus === "Novio (a)")
    ? document.getElementById("public-member-spouse").value.trim() : "";
  const ministry = document.getElementById("public-member-ministry").value;
  const baptized = document.getElementById("public-member-baptized").value;
  const birthday = document.getElementById("public-member-birthday").value;
  const profileFile = document.getElementById("public-member-avatar-file").files[0] || null;
  if (profileFile && (!profileFile.type.startsWith("image/") || profileFile.size > 2 * 1024 * 1024)) { showPublicMemberMessage("La foto debe ser una imagen y pesar como máximo 2 MB."); return; }

  if (name.length < 3 || phone.length < 7 || !email || !birthday || password.length < 8) {
    showPublicMemberMessage("Revisa tus datos. El correo es obligatorio y la contraseña debe tener al menos 8 caracteres.");
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
    let avatarUrl = null;
    if (profileFile) {
      const ext = (profileFile.name.split(".").pop() || "jpg").toLowerCase().replace(/[^a-z0-9]/g, "") || "jpg";
      const photoPath = "pending/" + requestId + "/" + crypto.randomUUID() + "." + ext;
      const { error: uploadError } = await window.supabaseClient.storage.from("profile-photos").upload(photoPath, profileFile, { contentType: profileFile.type, upsert: false });
      if (uploadError) throw uploadError;
      avatarUrl = window.supabaseClient.storage.from("profile-photos").getPublicUrl(photoPath).data.publicUrl;
    }

    const { data, error } = await window.supabaseClient.auth.signUp({
      email,
      password,
      options: {
        data: { nombre: name, tipo_cuenta: "miembro", solicitud_id: requestId, avatar_url: avatarUrl },
        emailRedirectTo: window.location.origin
      }
    });
    if (error) throw error;
    if (!data.user) throw new Error("Supabase no devolvió la cuenta creada. Contacta al administrador.");

    // Supabase puede ocultar la existencia de correos duplicados cuando la confirmación
    // está activada. En ese caso no se debe presentar la solicitud como completada.
    if (Array.isArray(data.user.identities) && data.user.identities.length === 0) {
      throw new Error("Este correo ya tiene una cuenta o no está disponible. Si ya te registraste, inicia sesión o contacta al administrador.");
    }

    if (data.session) await window.supabaseClient.auth.signOut();

    form.reset();
    togglePublicSpouseField();
    showPublicMemberMessage(
      "¡Solicitud y cuenta creadas! Revisa tu correo para confirmar la dirección, si se te solicita. Tu acceso seguirá bloqueado hasta que un administrador apruebe tu incorporación.",
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
  if (window.lucide) lucide.createIcons();
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
  const canManageMembers = (hasRole("admin") || hasRole("pastor") || hasRole("lider") || hasRole("servidor"));
  const canPastoralNotes = isAdmin || hasRole("pastor");
  const canLeaderNotes = canPastoralNotes || hasRole("lider");

  const btnAddMember = document.getElementById("btn-add-member");
  const btnAddRequest = document.getElementById("btn-add-request");
  const btnManageUsers = document.getElementById("btn-manage-users");
  const notesField = document.getElementById("notes-field");
  const notesSection = document.getElementById("view-notes-section");
  const leaderNotesField = document.getElementById("leader-notes-field");
  const leaderNotesSection = document.getElementById("view-leader-notes-section");
  if (notesField) notesField.classList.toggle("hidden", !canPastoralNotes);
  if (notesSection) notesSection.classList.toggle("hidden", !canPastoralNotes);
  // Las notas de líderes se administran en el editor privado por autor, no en la ficha del miembro.
  if (leaderNotesField) leaderNotesField.classList.add("hidden");
  if (leaderNotesSection) leaderNotesSection.classList.toggle("hidden", !canLeaderNotes);

  // Líder puede gestionar miembros; Servidor puede consultar y crear.
  if (btnAddMember) btnAddMember.classList.toggle("hidden", !canManageMembers);
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
    document.getElementById("users-modal").classList.remove("hidden");
    lucide.createIcons();
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

async function createSupabaseBackup() {
  if (!currentUser || !hasRole("admin")) {
    alert("Solo un administrador puede crear copias de seguridad.");
    return;
  }

  const button = document.querySelector('button[onclick="createSupabaseBackup()"]');
  if (button) button.disabled = true;
  setSupabaseBackupStatus("Consultando Supabase y preparando el archivo...");

  try {
    const [membersRows, requestRows, notesRows] = await Promise.all([
      readSupabaseTableForBackup("miembros_app"),
      readSupabaseTableForBackup("peticiones_oracion"),
      readSupabaseTableForBackup("notas_pastorales")
    ]);

    const backup = {
      app: "Iglesia Renacer - Control Congregacional",
      format: "renacer-supabase-backup",
      schemaVersion: 1,
      exportedAt: new Date().toISOString(),
      exportedBy: currentUser.name || "Administrador",
      source: "Supabase",
      data: {
        miembros_app: membersRows,
        peticiones_oracion: requestRows,
        notas_pastorales: notesRows.map(row => ({
          miembro_id: row.miembro_id,
          nota: row.nota,
          updated_at: row.updated_at
        }))
      }
    };

    const dateStr = new Date().toISOString().slice(0, 10);
    const filename = "Iglesia_Renacer_Supabase_Backup_" + dateStr + ".json";
    downloadFile(JSON.stringify(backup, null, 2), filename, "application/json");
    setSupabaseBackupStatus(
      "Copia creada: " + membersRows.length + " miembros, " +
      requestRows.length + " peticiones y " + notesRows.length + " notas pastorales."
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
      parsed.schemaVersion === 1 &&
      data &&
      Array.isArray(data.miembros_app) &&
      Array.isArray(data.peticiones_oracion) &&
      Array.isArray(data.notas_pastorales);

    if (!validFormat) {
      throw new Error("El archivo no es una copia de Supabase válida de Iglesia Renacer o su versión no es compatible.");
    }

    const validMembers = data.miembros_app.every(row =>
      row && typeof row.id === "string" && row.id.length > 0
    );
    const validRequests = data.peticiones_oracion.every(row =>
      row && typeof row.id === "string" && row.id.length > 0
    );
    const validNotes = data.notas_pastorales.every(row =>
      row && typeof row.miembro_id === "string" &&
      typeof row.nota === "string"
    );
    if (!validMembers || !validRequests || !validNotes) {
      throw new Error("El archivo contiene registros sin identificadores válidos.");
    }

    const confirmed = confirm(
      "Vas a restaurar desde: " + file.name + "\n\n" +
      "Miembros: " + data.miembros_app.length + "\n" +
      "Peticiones: " + data.peticiones_oracion.length + "\n" +
      "Notas pastorales: " + data.notas_pastorales.length + "\n\n" +
      "Los registros con el mismo ID serán actualizados y los que falten serán recuperados. " +
      "Los registros actuales que no estén en el archivo NO se eliminarán. " +
      "¿Deseas continuar?"
    );
    if (!confirmed) {
      setSupabaseBackupStatus("Restauración cancelada.");
      return;
    }

    setSupabaseBackupStatus("Restaurando miembros...");
    const upsertInBatches = async (table, rows, conflict) => {
      const batchSize = 100;
      for (let i = 0; i < rows.length; i += batchSize) {
        const batch = rows.slice(i, i + batchSize);
        const { error } = await window.supabaseClient
          .from(table)
          .upsert(batch, { onConflict: conflict });
        if (error) throw new Error("Error en " + table + ": " + error.message);
      }
    };

    await upsertInBatches("miembros_app", data.miembros_app, "id");
    setSupabaseBackupStatus("Restaurando peticiones...");
    await upsertInBatches("peticiones_oracion", data.peticiones_oracion, "id");
    setSupabaseBackupStatus("Restaurando notas pastorales...");
    await upsertInBatches("notas_pastorales", data.notas_pastorales, "miembro_id");

    await refreshCloudData();
    renderDashboard();
    renderTable();
    renderRequests();
    renderBirthdayModule();

    setSupabaseBackupStatus("Restauración completada. Los datos ya están sincronizados con Supabase.");
    alert("Restauración completada correctamente. Se recuperaron o actualizaron los registros del archivo.");
  } catch (error) {
    console.error("Error restaurando copia de Supabase:", error);
    setSupabaseBackupStatus("No se pudo completar la restauración: " + error.message, true);
    alert("No se pudo completar la restauración: " + error.message +
      "\n\nLos registros procesados antes del error podrían haberse guardado. Revisa los datos antes de repetirla.");
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
  alert("Para desactivar una cuenta, desactiva el usuario en Supabase Auth y cambia activo a FALSE en perfiles_app.");
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
  const allowedRoles = ["admin", "pastor", "lider", "servidor", "miembro"];
  const targetUser = users.find(user => user.id === userId);
  const nextRoles = Array.from(selectElement.selectedOptions).map(option => option.value);
  if (!targetUser || userId === currentUser.id || !nextRoles.length || nextRoles.some(role => !allowedRoles.includes(role)) || new Set(nextRoles).size !== nextRoles.length) {
    alert("Selecciona al menos un rol válido. No puedes modificar tu propia asignación."); renderUsersTable(); return;
  }
  if (JSON.stringify([...nextRoles].sort()) === JSON.stringify([...(targetUser.roles || [])].sort())) return;
  if (!confirm("¿Asignar a " + targetUser.name + " estos roles independientes: " + nextRoles.map(roleDisplayName).join(" + ") + "?")) { renderUsersTable(); return; }
  const { error } = await window.supabaseClient.from("perfiles_app").update({ roles: nextRoles }).eq("id", userId);
  if (error) { alert("No se pudieron actualizar los roles: " + error.message); renderUsersTable(); return; }
  await loadProfilesFromCloud(); renderUsersTable();
  alert("Roles actualizados. El usuario deberá actualizar la página para aplicar los permisos.");
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

  await loadProfilesFromCloud();
  renderUsersTable();
  alert(normalizedMemberId
    ? "Cuenta vinculada correctamente con el miembro seleccionado."
    : "La cuenta quedó desvinculada del registro de miembros.");
}

function renderUsersTable() {
  const tbody = document.getElementById("users-table-body");
  tbody.innerHTML = "";

  users.forEach(user => {
    const tr = document.createElement("tr");
    tr.className = "hover:bg-slate-50 dark:hover:bg-slate-700/50";

    const roleChoices = [
      { value: "admin", label: "Administrador" },
      { value: "pastor", label: "Pastor" },
      { value: "lider", label: "Líder" },
      { value: "servidor", label: "Servidor" },
      { value: "miembro", label: "Miembro" }
    ];
    const selectedRoles = new Set(Array.isArray(user.roles) ? user.roles : []);
    const roleOptions = roleChoices.map(choice =>
      '<option value="' + choice.value + '"' + (selectedRoles.has(choice.value) ? " selected" : "") + '>' + choice.label + '</option>'
    ).join("");
    const roleControl = '<div class="space-y-1"><select multiple size="5" id="user-roles-' + escapeHtml(user.id) + '" aria-label="Roles independientes de ' + escapeHtml(user.name) + '" ' +
      (user.id === currentUser.id ? "disabled " : "") +
      'class="min-w-[125px] max-w-[150px] px-2 py-1 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-[10px]">' + roleOptions + '</select>' +
      (user.id === currentUser.id ? '' : '<button type="button" data-user-id="' + escapeHtml(user.id) + '" onclick="saveUserRoles(this.dataset.userId)" class="text-[10px] px-2 py-1 rounded bg-church-800 text-white">Guardar roles</button>') + '</div>';
    const memberOptions = '<option value="">Sin vincular</option>' + members.map(member =>
      '<option value="' + escapeHtml(member.id) + '"' + (user.memberId === member.id ? " selected" : "") + '>' +
      escapeHtml(member.name) + '</option>'
    ).join("");
    const memberControl = '<select aria-label="Vincular miembro a ' + escapeHtml(user.name) + '" ' +
      (user.id === currentUser.id ? "disabled " : "") +
      'onchange="linkUserToMember(\'' + escapeHtml(user.id) + '\', this.value)" ' +
      'class="min-w-[150px] max-w-[210px] px-2 py-1 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-[10px]">' +
      memberOptions + '</select>';

    let statusAction = "";
    if (user.active || user.requestStatus === "aprobado") {
      statusAction = '<span class="text-emerald-600 dark:text-emerald-400">Aprobado</span>';
    } else if (user.requestStatus === "rechazado") {
      statusAction = '<span class="text-rose-600 dark:text-rose-400">Rechazado</span>';
    } else {
      statusAction = '<span class="text-amber-600 dark:text-amber-400">Pendiente de aprobación de incorporación</span>';
    }

    tr.innerHTML =
      '<td class="py-2.5 px-3 font-medium text-slate-900 dark:text-white">' + escapeHtml(user.name) + '</td>' +
      '<td class="py-2.5 px-3 font-mono text-slate-500 dark:text-slate-400">' + escapeHtml(user.username) + '</td>' +
      '<td class="py-2.5 px-3"><div class="space-y-1">' + roleControl + '<div class="text-[10px] text-slate-400">Roles independientes (Ctrl / Cmd para varios)</div></div></td>' +
      '<td class="py-2.5 px-3"><div class="space-y-1">' + memberControl + '<div class="text-[10px] text-slate-400">' + (user.memberId ? 'Miembro vinculado' : 'Sin miembro asociado') + '</div></div></td>' +
      '<td class="py-2.5 px-3 text-right text-slate-500">' + statusAction + '</td>';

    tbody.appendChild(tr);
  });

  lucide.createIcons();
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
    meta.textContent = "Publicado " + formatAnnouncementDate(item.creado_en);
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
  if (window.lucide) lucide.createIcons();
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
  if (window.lucide) lucide.createIcons();
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
        titulo, contenido, creado_por: currentUser.id
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

function renderDashboard() {
  renderPersonalWelcomeCard();
  const total = members.length;
  const active = members.filter(m => m.status === 'Activo').length;
  const visits = members.filter(m => m.status === 'En Visita').length;
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
  return members.filter(m => {
    if (!m.birthday) return false;
    const parts = m.birthday.split('-');
    return parts.length >= 2 && parts[1] === monthSelect;
  });
}

function renderBirthdayModule() {
  const container = document.getElementById('birthday-module-list');
  const emptyState = document.getElementById('birthday-module-empty');
  const birthdayMembers = getBirthdayMembersForSelectedMonth();

  container.innerHTML = '';

  if (birthdayMembers.length === 0) {
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');
    birthdayMembers.forEach(m => {
      const card = document.createElement('div');
      card.className = "bg-slate-50 dark:bg-slate-900/60 p-3 rounded-lg border border-slate-200 dark:border-slate-700/80 flex items-center justify-between";
      
      const initials = m.name.split(' ').map(n => n[0]).slice(0,2).join('').toUpperCase();
      let avatarHtml = `<div class="w-8 h-8 rounded-full bg-church-800 text-amber-300 font-bold flex items-center justify-center text-xs shrink-0">${escapeHtml(initials)}</div>`;
      if (m.avatar) {
        avatarHtml = `<div class="w-8 h-8 rounded-full overflow-hidden shrink-0 border border-amber-400/40"><img src="${escapeHtml(m.avatar)}" class="w-full h-full object-cover"></div>`;
      }

      let birthYearText = "";
      if (m.birthday) {
        const parts = m.birthday.split('-');
        if (parts.length === 3) {
          const year = parts[0];
          const dayMonth = `${parts[2]}/${parts[1]}`;
          birthYearText = `🎂 ${dayMonth} (${year})`;
        }
      }

      card.innerHTML = `
        <div class="flex items-center gap-2.5 overflow-hidden">
          ${avatarHtml}
          <div class="truncate">
            <p class="text-xs font-semibold text-slate-800 dark:text-white truncate">${escapeHtml(m.name)}</p>
            <p class="text-[11px] text-amber-600 dark:text-amber-400 font-medium">${escapeHtml(birthYearText)}</p>
          </div>
        </div>
        <a href="https://api.whatsapp.com/send?text=${encodeURIComponent('¡Feliz Cumpleaños ' + m.name + '! Que Dios te bendiga grandemente en este día. 🎂🎉 - Iglesia Renacer')}" target="_blank" title="Felicitar por WhatsApp" class="p-1.5 bg-emerald-50 hover:bg-emerald-100 text-emerald-600 rounded-lg transition shrink-0">
          <i data-lucide="share-2" class="w-3.5 h-3.5"></i>
        </a>
      `;
      container.appendChild(card);
    });
  }
  lucide.createIcons();
}

function shareBirthdays(format) {
  const monthSelect = document.getElementById('share-birthday-month').value;
  const monthNames = {
    "01": "Enero", "02": "Febrero", "03": "Marzo", "04": "Abril", 
    "05": "Mayo", "06": "Junio", "07": "Julio", "08": "Agosto", 
    "09": "Septiembre", "10": "Octubre", "11": "Noviembre", "12": "Diciembre"
  };

  const birthdayMembers = getBirthdayMembersForSelectedMonth();

  if (birthdayMembers.length === 0) {
    alert(`No hay hermanos registrados con fecha de cumpleaños en el mes de ${monthNames[monthSelect]}.`);
    return;
  }

  let textContent = `🎂 CUMPLEAÑEROS DE ${monthNames[monthSelect].toUpperCase()} - IGLESIA RENACER\n\n`;
  birthdayMembers.forEach((m, idx) => {
    textContent += `${idx + 1}. ${m.name} - Fecha: ${m.birthday} (Tel: ${m.phone})\n`;
  });

  if (format === 'txt') {
    downloadFile(textContent, `Cumpleanos_${monthNames[monthSelect]}.txt`, 'text/plain');
  } else if (format === 'whatsapp') {
    const encodedText = encodeURIComponent(textContent);
    window.open(`https://api.whatsapp.com/send?text=${encodedText}`, '_blank');
  } else if (format === 'image') {
    generateImage(`Cumpleaños de ${monthNames[monthSelect]}`, birthdayMembers.map(m => `${m.name} (${m.birthday})`), `Cumpleanos_${monthNames[monthSelect]}.png`);
  }
}

function getFilteredRequests() {
  const searchVal = document.getElementById('search-request-input').value.toLowerCase().trim();
  const timeFilter = document.getElementById('filter-request-time').value;
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

    return matchesSearch && matchesTime;
  });
}

function renderRequests() {
  const container = document.getElementById('requests-container');
  const emptyState = document.getElementById('requests-empty-state');
  const filtered = getFilteredRequests();
  const canEdit = currentUser && (hasRole("admin") || hasRole("pastor") || hasRole("lider") || hasRole("servidor"));

  container.innerHTML = '';

  if (filtered.length === 0) {
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');

    filtered.forEach(req => {
      const member = members.find(m => m.id === req.memberId);
      const memberName = req.memberName || (member ? member.name : 'Hermano General');
      const memberMinistry = member ? (member.ministry || 'General') : 'Sin ministerio';
      
      const reqDate = new Date(req.createdAt);
      const timeFormatted = reqDate.toLocaleDateString() + ' ' + reqDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      const card = document.createElement('div');
      card.className = "bg-slate-50 dark:bg-slate-900/60 p-4 rounded-xl border border-slate-200 dark:border-slate-700/80 flex flex-col justify-between space-y-3";

      card.innerHTML = `
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold px-2.5 py-0.5 rounded-md bg-amber-50 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 border border-amber-200/50">
              ${escapeHtml(memberMinistry)}
            </span>
            <span class="text-xs text-slate-400 flex items-center gap-1">
              <i data-lucide="clock" class="w-3 h-3"></i> ${escapeHtml(timeFormatted)}
            </span>
          </div>
          <p class="text-sm font-medium text-slate-800 dark:text-slate-200 mt-2">"${escapeHtml(req.text)}"</p>
        </div>
        <div class="flex items-center justify-between pt-2 border-t border-slate-200/60 dark:border-slate-800 text-xs">
          <span class="font-semibold text-slate-700 dark:text-slate-300">Hermano: ${escapeHtml(memberName)}</span>
          ${canEdit ? `
          <button onclick="deleteRequest('${escapeHtml(req.id)}')" title="Eliminar petición" class="text-slate-400 hover:text-rose-600 transition">
            <i data-lucide="trash-2" class="w-4 h-4"></i>
          </button>` : ''}
        </div>
      `;
      container.appendChild(card);
    });
  }

  lucide.createIcons();
}

function shareRequests(format) {
  const filtered = getFilteredRequests();
  if (filtered.length === 0) {
    alert("No hay peticiones de oración para exportar.");
    return;
  }

  const dateStr = new Date().toLocaleDateString('es-ES');
  let textContent = `🙏 PETICIONES DE ORACIÓN - IGLESIA RENACER (${dateStr})\n\n`;
  
  filtered.forEach((req, index) => {
    const member = members.find(m => m.id === req.memberId);
    const name = member ? member.name : 'Hermano';
    textContent += `${index + 1}. ${name}: "${req.text}"\n`;
  });

  if (format === 'txt') {
    downloadFile(textContent, `Peticiones_Oracion_${dateStr.replace(/\//g, '-')}.txt`, 'text/plain');
  } else if (format === 'whatsapp') {
    const encodedText = encodeURIComponent(textContent);
    window.open(`https://api.whatsapp.com/send?text=${encodedText}`, '_blank');
  } else if (format === 'image') {
    generateImage("Peticiones de Oración", filtered.map(r => {
      const m = members.find(mem => mem.id === r.memberId);
      return `${m ? m.name : 'Hermano'}: "${r.text}"`;
    }), "peticiones_oracion.png");
  }
}

function shareVisits(format) {
  const visits = members.filter(m => m.status === 'En Visita');
  if (visits.length === 0) {
    alert("No hay registros de personas en estado 'En Visita' para exportar.");
    return;
  }

  const dateStr = new Date().toLocaleDateString('es-ES');
  let textContent = `🤝 LISTA DE VISITAS - IGLESIA RENACER (${dateStr})\n\n`;
  
  visits.forEach((v, index) => {
    textContent += `${index + 1}. ${v.name} - Tel: ${v.phone} (${v.notes || 'Sin notas'})\n`;
  });

  if (format === 'txt') {
    downloadFile(textContent, `Visitas_${dateStr.replace(/\//g, '-')}.txt`, 'text/plain');
  } else if (format === 'whatsapp') {
    const encodedText = encodeURIComponent(textContent);
    window.open(`https://api.whatsapp.com/send?text=${encodedText}`, '_blank');
  } else if (format === 'image') {
    generateImage("Hermanos En Visita", visits.map(v => `${v.name} - Tel: ${v.phone}`), "lista_visitas.png");
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

function generateImage(title, items, filename) {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');

  const width = 800;
  const lineHeight = 40;
  const padding = 50;
  const height = padding * 2 + 100 + items.length * lineHeight;

  canvas.width = width;
  canvas.height = height;

  const gradient = ctx.createLinearGradient(0, 0, 0, height);
  gradient.addColorStop(0, '#102a43');
  gradient.addColorStop(1, '#0b1b2b');
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, width, height);

  ctx.fillStyle = '#f59e0b';
  ctx.font = 'bold 28px Inter, sans-serif';
  ctx.fillText('Iglesia Renacer', padding, padding + 30);

  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 22px Inter, sans-serif';
  ctx.fillText(title, padding, padding + 70);

  ctx.strokeStyle = '#f59e0b';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(padding, padding + 85);
  ctx.lineTo(width - padding, padding + 85);
  ctx.stroke();

  ctx.fillStyle = '#e2e8f0';
  ctx.font = '16px Inter, sans-serif';
  
  let y = padding + 125;
  items.forEach((item, idx) => {
    const text = `${idx + 1}. ${item}`;
    ctx.fillText(text.length > 75 ? text.substring(0, 72) + '...' : text, padding, y);
    y += lineHeight;
  });

  const link = document.createElement('a');
  link.download = filename;
  link.href = canvas.toDataURL('image/png');
  link.click();
}

let privateNoteContext = null;
async function openPrivateNoteModal(memberId, type) {
  const member = members.find(item => String(item.id) === String(memberId));
  if (!member || !currentUser) return;
  if (type === "pastoral" && !(hasRole("admin") || hasRole("pastor"))) return;
  if (type === "leader" && !hasRole("lider")) return;
  privateNoteContext = { memberId: String(memberId), type };
  document.getElementById("private-note-title").textContent = type === "pastoral" ? "Nota pastoral privada" : "Nota personal de líder";
  document.getElementById("private-note-member").textContent = member.name;
  const field = document.getElementById("private-note-text");
  if (type === "pastoral") field.value = member.notes || "";
  else {
    const { data, error } = await window.supabaseClient.from("notas_lideres").select("nota")
      .eq("miembro_id", String(memberId)).eq("lider_id", currentUser.id).maybeSingle();
    if (error) { alert("No se pudo cargar la nota: " + error.message); return; }
    field.value = data ? data.nota || "" : "";
  }
  document.getElementById("private-note-modal").classList.remove("hidden");
}
function closePrivateNoteModal() {
  document.getElementById("private-note-modal").classList.add("hidden");
  privateNoteContext = null;
}
async function savePrivateNote(event) {
  event.preventDefault();
  if (!privateNoteContext || !currentUser) return;
  const member = members.find(item => String(item.id) === privateNoteContext.memberId);
  if (!member) return;
  const note = document.getElementById("private-note-text").value.trim();
  const now = new Date().toISOString();
  let result;
  if (privateNoteContext.type === "pastoral") {
    if (!(hasRole("admin") || hasRole("pastor"))) return;
    result = await window.supabaseClient.from("notas_pastorales").upsert({
      miembro_id: privateNoteContext.memberId, nota: note, updated_at: now, updated_by: currentUser.id
    }, { onConflict: "miembro_id" });
    if (!result.error) member.notes = note;
  } else {
    if (!hasRole("lider")) return;
    result = await window.supabaseClient.from("notas_lideres").upsert({
      miembro_id: privateNoteContext.memberId, lider_id: currentUser.id, nota: note,
      updated_at: now, updated_by: currentUser.id
    }, { onConflict: "miembro_id,lider_id" });
    if (!result.error) member.leaderNotes = note ? "Mi nota: " + note : "";
  }
  if (result.error) { alert("No se pudo guardar la nota: " + result.error.message); return; }
  closePrivateNoteModal();
  alert("Nota guardada correctamente.");
}

function renderTable() {
  const tbody = document.getElementById('members-table-body');
  const emptyState = document.getElementById('empty-state');
  if (!tbody) return;

  const searchVal = document.getElementById('search-input').value.toLowerCase().trim();
  const maritalFilter = document.getElementById('filter-marital-status').value;
  const ministryFilter = document.getElementById('filter-ministry').value;
  const statusFilter = document.getElementById('filter-status').value;

  const canEdit = currentUser && (hasRole("admin") || hasRole("pastor") || hasRole("lider"));
  const canAddPastoralNote = currentUser && (hasRole("admin") || hasRole("pastor"));
  const canAddLeaderNote = currentUser && hasRole("lider");

  tbody.innerHTML = '';

  const filtered = members.filter(m => {
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

  lucide.createIcons();
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

function openModal(isEdit = false) {
  if (!currentUser || !(hasRole("admin") || hasRole("pastor") || hasRole("lider") || hasRole("servidor")) || (isEdit && hasRole("servidor") && !hasRole("admin") && !hasRole("pastor") && !hasRole("lider"))) return;
  const modal = document.getElementById('member-modal');
  const title = document.getElementById('modal-title');
  
  if (!isEdit) {
    document.getElementById('member-form').reset();
    document.getElementById('member-id').value = '';
    document.getElementById('input-birthday').value = new Date().toISOString().split('T')[0];
    document.getElementById('input-marital-status').value = 'Soltero (a)';
    currentAvatarBase64 = "";
    
    document.getElementById('avatar-preview-img').classList.add('hidden');
    document.getElementById('avatar-preview-initials').classList.remove('hidden');
    document.getElementById('avatar-preview-initials').textContent = '--';

    handleMaritalStatusChange();
    title.textContent = 'Agregar Nuevo Hermano';
  } else {
    title.textContent = 'Editar Información del Hermano';
  }
  modal.classList.remove('hidden');
}

function closeModal() {
  document.getElementById('member-modal').classList.add('hidden');
}

function openRequestModal() {
  if (!currentUser) return;
  document.getElementById("request-form").reset();
  document.getElementById("request-member-name").value = currentUser.name || "";
  if (isMemberOnly() && !currentUser.memberId) {
    alert("Tu usuario no tiene vinculado un registro de miembro. Contacta al administrador.");
    return;
  }
  document.getElementById('request-modal').classList.remove('hidden');
  lucide.createIcons();
}

function closeRequestModal() {
  document.getElementById('request-modal').classList.add('hidden');
}

async function handleRequestSubmit(e) {
  e.preventDefault();
  if (!currentUser) return;

  const memberId = isMemberOnly() ? currentUser.memberId : null;
  const memberName = document.getElementById("request-member-name").value.trim();
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
.select("id,member_id,member_name,description,created_at")
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
  if (!currentUser || !(hasRole("admin") || hasRole("pastor") || hasRole("lider") || hasRole("servidor"))) return;
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
  if (!currentUser || !(hasRole("admin") || hasRole("pastor") || hasRole("lider") || hasRole("servidor"))) return;

  const id = document.getElementById("member-id").value;
  if (id && hasRole("servidor") && !hasRole("admin") && !hasRole("pastor") && !hasRole("lider")) {
    alert("El rol Servidor solo puede crear miembros, no editar registros existentes.");
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
    status: document.getElementById("input-status").value,
    baptized: document.getElementById("input-baptized").value,
    birthday: document.getElementById("input-birthday").value || "",
    notes: document.getElementById("input-notes").value.trim(),
    avatar: avatarToSave
  };

  if (id) {
    const index = members.findIndex(member => member.id === id);
    if (index !== -1) members[index] = memberData;
  } else {
    members.unshift(memberData);
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
    if (hasRole("servidor") && !hasRole("admin") && !hasRole("pastor")) {
      const { error } = await window.supabaseClient.from("miembros_app").insert(mapAppMemberToDb(memberData));
      if (error) throw error;
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
  if (!currentUser || !(hasRole("admin") || hasRole("pastor") || hasRole("lider"))) return;
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
}

async function deleteMember(id) {
  if (!currentUser || !(hasRole("admin") || hasRole("pastor") || hasRole("lider"))) return;

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
  document.getElementById('view-notes').textContent = member.notes || 'Sin observaciones pastorales.';
  const leaderNotesText = document.getElementById('view-leader-notes');
  if (leaderNotesText) leaderNotesText.textContent = member.leaderNotes || 'Sin notas de líderes.';
  const ownPhotoControls = document.getElementById("view-own-photo-controls");
  if (ownPhotoControls) ownPhotoControls.classList.toggle("hidden", !(currentUser && currentUser.memberId && String(currentUser.memberId) === String(member.id)));

  document.getElementById('details-modal').classList.remove('hidden');
  lucide.createIcons();
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
  lucide.createIcons();
});
