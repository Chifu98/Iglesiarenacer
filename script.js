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
let members = [];
let prayerRequests = [];
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
    notes: "", // Las notas pastorales se cargan por separado y solo para administradores.
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
  const [membersResult, requestsResult] = await Promise.all([
    client.from("miembros_app").select("*").order("created_at", { ascending: false }),
    client.from("peticiones_oracion").select("*").order("created_at", { ascending: false })
  ]);

  if (membersResult.error) throw membersResult.error;
  if (requestsResult.error) throw requestsResult.error;

  let privateNotes = new Map();
  if (currentUser && currentUser.role === "admin") {
    const notesResult = await client
      .from("notas_pastorales")
      .select("miembro_id,nota");
    if (notesResult.error) throw notesResult.error;
    privateNotes = new Map((notesResult.data || []).map(row => [row.miembro_id, row.nota || ""]));
  }

  members = (membersResult.data || []).map(row => ({
    ...mapDbMemberToApp(row),
    notes: privateNotes.get(row.id) || ""
  }));
  prayerRequests = (requestsResult.data || []).map(mapDbRequestToApp);
}

async function saveMembers() {
  if (!members.length) return;
  const rows = members.map(mapAppMemberToDb);
  const { error } = await window.supabaseClient
    .from("miembros_app")
    .upsert(rows, { onConflict: "id" });

  if (error) throw error;

  // Las notas pastorales se guardan en una tabla separada con RLS exclusiva de administradores.
  if (currentUser && currentUser.role === "admin") {
    const privateRows = members.map(member => ({
      miembro_id: String(member.id),
      nota: member.notes || "",
      updated_at: new Date().toISOString(),
      updated_by: currentUser.id
    }));

    if (privateRows.length) {
      const { error: notesError } = await window.supabaseClient
        .from("notas_pastorales")
        .upsert(privateRows, { onConflict: "miembro_id" });
      if (notesError) throw notesError;
    }
  }
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

  if (currentUser.role !== "admin") {
    users = [currentUser];
    return;
  }

  const { data, error } = await window.supabaseClient
    .from("perfiles_app")
    .select("id,nombre,usuario,rol,activo")
    .order("nombre", { ascending: true });

  if (error) throw error;

  users = (data || []).map(profile => ({
    id: profile.id,
    name: profile.nombre,
    username: profile.usuario || profile.id,
    role: profile.rol,
    active: profile.activo
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

    const { data: profile, error: profileError } = await window.supabaseClient
      .from("perfiles_app")
      .select("id,nombre,usuario,rol,activo")
      .eq("id", session.user.id)
      .maybeSingle();

    if (profileError) throw profileError;

    if (!profile || !profile.activo) {
      await window.supabaseClient.auth.signOut();
      currentUser = null;
      showLoginView();
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
      role: profile.rol
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
    const errorDiv = document.getElementById("login-error");
    errorDiv.textContent = "No se pudo cargar tu perfil o los datos. Revisa tu conexión y los permisos de Supabase.";
    errorDiv.classList.remove("hidden");
  }
}

function showSignupForm() {
  document.getElementById("signup-form").classList.remove("hidden");
  document.getElementById("signup-message").classList.add("hidden");
  document.getElementById("login-error").classList.add("hidden");
  document.getElementById("signup-name").focus();
}

function hideSignupForm() {
  document.getElementById("signup-form").classList.add("hidden");
  document.getElementById("signup-form").reset();
}

function showSignupMessage(message, success = false) {
  const box = document.getElementById("signup-message");
  box.textContent = message;
  box.className = "p-3 rounded-xl text-xs " + (success
    ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-300"
    : "bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300");
}

async function handleSignup(event) {
  event.preventDefault();
  const name = document.getElementById("signup-name").value.trim();
  const email = document.getElementById("signup-email").value.trim().toLowerCase();
  const password = document.getElementById("signup-password").value;
  const button = document.getElementById("signup-submit");
  if (!name || !email || password.length < 8) {
    showSignupMessage("Completa los datos y utiliza una contraseña de al menos 8 caracteres.");
    return;
  }

  button.disabled = true;
  button.textContent = "Enviando...";
  try {
    const { data, error } = await window.supabaseClient.auth.signUp({
      email,
      password,
      options: {
        data: { nombre: name },
        emailRedirectTo: window.location.origin
      }
    });
    if (error) throw error;

    // Nunca se permite acceso automático: la aprobación del administrador es obligatoria.
    if (data.session) await window.supabaseClient.auth.signOut();
    document.getElementById("signup-form").reset();
    showSignupMessage(
      "Solicitud enviada. Si Supabase requiere confirmar tu correo, revisa tu bandeja de entrada. Después de confirmar, un administrador deberá aprobar tu cuenta. No podrás ingresar antes de esa aprobación.",
      true
    );
  } catch (error) {
    console.error("Error solicitando cuenta:", error);
    showSignupMessage("No se pudo enviar la solicitud: " + error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Enviar solicitud";
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
  showLoginView();
}

function showLoginView() {
  document.getElementById("login-view").classList.remove("hidden");
  document.getElementById("app-container").classList.add("hidden");
}

function showAppView() {
  document.getElementById("login-view").classList.add("hidden");
  document.getElementById("app-container").classList.remove("hidden");

  document.getElementById("current-user-name").textContent = currentUser.name;
  const badge = document.getElementById("current-user-role-badge");
  badge.textContent = currentUser.role.toUpperCase();

  applyRolePermissions();
  renderDashboard();
  renderTable();
  renderRequests();
  renderBirthdayModule();
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
      { event: "*", schema: "public", table: "notas_pastorales" },
      scheduleCloudRefresh
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
      renderBirthdayModule();
    } catch (error) {
      console.error("Error sincronizando los datos:", error);
    }
  }, 350);
}

function applyRolePermissions() {
  const isLectura = currentUser.role === "lectura";
  const isAdmin = currentUser.role === "admin";

  const btnAddMember = document.getElementById("btn-add-member");
  const btnAddRequest = document.getElementById("btn-add-request");
  const btnManageUsers = document.getElementById("btn-manage-users");
  const notesField = document.getElementById("notes-field");
  const notesSection = document.getElementById("view-notes-section");

  if (notesField) notesField.classList.toggle("hidden", !isAdmin);
  if (notesSection) notesSection.classList.toggle("hidden", !isAdmin);

  // Lectura puede consultar todos los módulos y registrar peticiones,
  // pero no puede crear/editar miembros ni administrar usuarios.
  if (btnAddMember) btnAddMember.classList.toggle("hidden", isLectura);
  if (btnAddRequest) btnAddRequest.classList.remove("hidden");

  if (isAdmin) {
    btnManageUsers.classList.remove("hidden");
  } else {
    btnManageUsers.classList.add("hidden");
  }
}

/* USER MANAGEMENT (ADMIN ROLE) */
async function openUsersModal() {
  if (!currentUser || currentUser.role !== "admin") return;

  try {
    await loadProfilesFromCloud();
    renderUsersTable();
    document.getElementById("users-modal").classList.remove("hidden");
    lucide.createIcons();
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

function exportFullDatabase() {
  if (!currentUser || currentUser.role !== "admin") return;

  const fullData = {
    app: "Iglesia Renacer - Control Congregacional",
    exportedAt: new Date().toISOString(),
    version: "2.0",
    data: {
      users: users.map(user => ({
        id: user.id,
        name: user.name,
        username: user.username,
        role: user.role,
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
  if (!currentUser || currentUser.role !== "admin") return;

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
  if (!currentUser || currentUser.role !== "admin") return;
  const requestedUser = users.find(user => user.id === userId);
  if (!requestedUser || requestedUser.role !== "lectura" || requestedUser.active) return;
  if (!confirm("¿Aprobar la cuenta de " + requestedUser.name + "? Se habilitará con permisos de lectura.")) return;

  const { error } = await window.supabaseClient
    .from("perfiles_app")
    .update({ activo: true })
    .eq("id", userId)
    .eq("rol", "lectura");
  if (error) {
    alert("No se pudo aprobar la cuenta: " + error.message);
    return;
  }
  await loadProfilesFromCloud();
  renderUsersTable();
  alert("Cuenta aprobada. El usuario ya puede iniciar sesión con permisos de lectura.");
}

function renderUsersTable() {
  const tbody = document.getElementById("users-table-body");
  tbody.innerHTML = "";

  users.forEach(user => {
    const tr = document.createElement("tr");
    tr.className = "hover:bg-slate-50 dark:hover:bg-slate-700/50";

    let roleBadge = "bg-slate-100 text-slate-700 border-slate-300";
    if (user.role === "admin") roleBadge = "bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-300 border-amber-300";
    if (user.role === "escritura") roleBadge = "bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border-blue-300";

    tr.innerHTML =
      '<td class="py-2.5 px-3 font-medium text-slate-900 dark:text-white">' + escapeHtml(user.name) + '</td>' +
      '<td class="py-2.5 px-3 font-mono text-slate-500 dark:text-slate-400">' + escapeHtml(user.username) + '</td>' +
      '<td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded-md border text-[10px] font-semibold uppercase ' + roleBadge + '">' + escapeHtml(user.role) + '</span></td>' +
      '<td class="py-2.5 px-3 text-right text-slate-500">' +
      (user.active
        ? '<span class="text-emerald-600 dark:text-emerald-400">Aprobado</span>'
        : (user.role === "lectura"
          ? '<div class="flex items-center justify-end gap-2"><span class="text-amber-600 dark:text-amber-400">Pendiente</span><button type="button" onclick="approveSignup(\'' + escapeHtml(user.id) + '\')" class="px-2 py-1 rounded-md bg-emerald-600 hover:bg-emerald-700 text-white text-[10px] font-semibold">Aprobar</button></div>'
          : '<span>Inactivo</span>')) + '</td>';

    tbody.appendChild(tr);
  });

  lucide.createIcons();
}



/* AUDITORÍA (SOLO ADMINISTRADORES) */
async function openAuditModal() {
  if (!currentUser || currentUser.role !== "admin") return;

  const modal = document.getElementById("audit-modal");
  modal.classList.remove("hidden");
  await loadAuditLog();
}

function closeAuditModal() {
  document.getElementById("audit-modal").classList.add("hidden");
}

async function loadAuditLog() {
  if (!currentUser || currentUser.role !== "admin") return;

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

/* RENDER DASHBOARD & METRICS */
/* RENDER DASHBOARD & METRICS */
function renderDashboard() {
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
  const canEdit = currentUser && (currentUser.role === 'admin' || currentUser.role === 'escritura');

  container.innerHTML = '';

  if (filtered.length === 0) {
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');

    filtered.forEach(req => {
      const member = members.find(m => m.id === req.memberId);
      const memberName = member ? member.name : 'Hermano General';
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

function renderTable() {
  const tbody = document.getElementById('members-table-body');
  const emptyState = document.getElementById('empty-state');
  if (!tbody) return;

  const searchVal = document.getElementById('search-input').value.toLowerCase().trim();
  const maritalFilter = document.getElementById('filter-marital-status').value;
  const ministryFilter = document.getElementById('filter-ministry').value;
  const statusFilter = document.getElementById('filter-status').value;

  const canEdit = currentUser && (currentUser.role === 'admin' || currentUser.role === 'escritura');

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
  if (currentUser.role === 'lectura') return;
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
  if (!currentUser || !['admin', 'escritura', 'lectura'].includes(currentUser.role)) return;
  const select = document.getElementById('request-member-select');
  select.innerHTML = '';
  members.forEach(m => {
    const opt = document.createElement('option');
    opt.value = m.id;
    opt.textContent = m.name;
    select.appendChild(opt);
  });
  document.getElementById('request-form').reset();
  document.getElementById('request-modal').classList.remove('hidden');
  lucide.createIcons();
}

function closeRequestModal() {
  document.getElementById('request-modal').classList.add('hidden');
}

async function handleRequestSubmit(e) {
  e.preventDefault();
  if (!currentUser || !['admin', 'escritura', 'lectura'].includes(currentUser.role)) return;

  const memberId = document.getElementById("request-member-select").value;
  const text = document.getElementById("request-description").value.trim();
  if (!text) {
    alert("Escribe el motivo de oración antes de guardar.");
    return;
  }

  const newReq = {
    id: "r_" + Date.now(),
    memberId: memberId,
    text: text,
    createdAt: new Date().toISOString()
  };

  try {
    // INSERT directo: evita que el rol lectura use upsert y pueda actualizar registros existentes.
    const { data, error } = await window.supabaseClient
      .from("peticiones_oracion")
      .insert({
        id: newReq.id,
        member_id: newReq.memberId || null,
        description: newReq.text,
        created_at: newReq.createdAt,
        created_by: currentUser.id
      })
      .select("id,member_id,description,created_at")
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
  if (!currentUser || currentUser.role === "lectura") return;
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
  if (!currentUser || currentUser.role === "lectura") return;

  const id = document.getElementById("member-id").value;
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
    await saveMembers();
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
  if (currentUser.role === 'lectura') return;
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
  if (!currentUser || currentUser.role === "lectura") return;

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

  document.getElementById('details-modal').classList.remove('hidden');
  lucide.createIcons();
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
