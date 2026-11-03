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
    .select("id,nombre,usuario,rol,activo,estado_solicitud")
    .order("nombre", { ascending: true });

  if (error) throw error;

  users = (data || []).map(profile => ({
    id: profile.id,
    name: profile.nombre,
    username: profile.usuario || profile.id,
    role: profile.rol,
    active: profile.activo,
    requestStatus: profile.estado_solicitud || (profile.activo ? "aprobado" : "pendiente")
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
      showAccessOption("servers");
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
    showAccessOption("servers");
    const errorDiv = document.getElementById("login-error");
    errorDiv.textContent = "No se pudo cargar tu perfil o los datos. Revisa tu conexión y los permisos de Supabase.";
    errorDiv.classList.remove("hidden");
  }
}

function showAccessOption(option) {
  const menu = document.getElementById("access-menu");
  const servers = document.getElementById("server-access-panel");
  const membersPanel = document.getElementById("public-member-panel");
  const loginError = document.getElementById("login-error");
  if (menu) menu.classList.toggle("hidden", option !== "menu");
  if (servers) servers.classList.toggle("hidden", option !== "servers");
  if (membersPanel) membersPanel.classList.toggle("hidden", option !== "members");
  if (loginError) loginError.classList.add("hidden");
  const signup = document.getElementById("signup-form");
  if (signup && option !== "servers") signup.classList.add("hidden");
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

  if (name.length < 3 || phone.length < 7 || !email || !birthday || password.length < 8) {
    showPublicMemberMessage("Revisa tus datos. El correo es obligatorio y la contraseña debe tener al menos 8 caracteres.");
    return;
  }

  button.disabled = true;
  button.textContent = "Creando cuenta y solicitud...";
  let requestId = null;
  try {
    const { data: request, error: requestError } = await window.supabaseClient
      .from("solicitudes_registro_miembros")
      .insert({
        name, phone, email, address: address || null,
        marital_status: maritalStatus,
        spouse_type: spouseName ? "text" : "none",
        spouse_name: spouseName || null, spouse_id: null,
        ministry, baptized, birthday, status: "Activo"
      })
      .select("id")
      .single();
    if (requestError) throw requestError;
    requestId = request.id;

    const { data, error } = await window.supabaseClient.auth.signUp({
      email,
      password,
      options: {
        data: { nombre: name, tipo_cuenta: "hermano", solicitud_id: requestId },
        emailRedirectTo: window.location.origin
      }
    });
    if (error) throw error;
    if (!data.user) throw new Error("Supabase no devolvió la cuenta creada. Contacta al administrador antes de volver a intentarlo.");
    if (data.session) await window.supabaseClient.auth.signOut();

    form.reset();
    togglePublicSpouseField();
    showPublicMemberMessage(
      "¡Solicitud y cuenta creadas! Revisa tu correo para confirmar la dirección, si se te solicita. Tu acceso seguirá bloqueado hasta que un administrador apruebe tu incorporación.",
      true
    );
  } catch (error) {
    console.error("Error creando solicitud/cuenta de hermano:", { error, requestId });
    showPublicMemberMessage(
      "No se pudo completar el registro. " +
      (requestId
        ? "La solicitud quedó registrada, pero la cuenta no se confirmó. Contacta al administrador para revisar y evitar solicitudes duplicadas. "
        : "") +
      (error.message || "Inténtalo nuevamente.")
    );
  } finally {
    button.disabled = false;
    button.textContent = "Enviar solicitud de registro";
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
  showAccessOption("menu");
  hideSignupForm();
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
    .on("postgres_changes",
      { event: "*", schema: "public", table: "solicitudes_registro_miembros" },
      () => { if (currentUser && currentUser.role === "admin" && !document.getElementById("users-modal").classList.contains("hidden")) loadPendingMemberRequests(); }
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
  if (!currentUser || currentUser.role !== "admin") {
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
  if (!currentUser || currentUser.role !== "admin") {
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
  if (!currentUser || currentUser.role !== "admin") return;
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

async function changeUserRole(userId, newRole) {
  if (!currentUser || currentUser.role !== "admin") return;
  const allowedRoles = ["admin", "escritura", "lectura"];
  const targetUser = users.find(user => user.id === userId);
  if (!targetUser || userId === currentUser.id || !allowedRoles.includes(newRole)) {
    renderUsersTable();
    return;
  }
  if (targetUser.role === newRole) return;
  if (!confirm("¿Cambiar el rol de " + targetUser.name + " de " + targetUser.role + " a " + newRole + "?")) {
    renderUsersTable();
    return;
  }

  const { error } = await window.supabaseClient
    .from("perfiles_app")
    .update({ rol: newRole })
    .eq("id", userId);
  if (error) {
    alert("No se pudo cambiar el rol: " + error.message);
    renderUsersTable();
    return;
  }
  await loadProfilesFromCloud();
  renderUsersTable();
  alert("Rol actualizado correctamente. Si el usuario tenía una sesión abierta, deberá actualizar la página para aplicar los nuevos permisos.");
}

function renderUsersTable() {
  const tbody = document.getElementById("users-table-body");
  tbody.innerHTML = "";

  users.forEach(user => {
    const tr = document.createElement("tr");
    tr.className = "hover:bg-slate-50 dark:hover:bg-slate-700/50";

    const roleOptions = ["admin", "escritura", "lectura"].map(role =>
      '<option value="' + role + '"' + (user.role === role ? " selected" : "") + '>' + role + '</option>'
    ).join("");
    const roleControl = user.role === "hermano"
      ? '<span class="inline-block px-2 py-1 rounded-md bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 text-[10px] font-semibold">hermano</span>'
      : '<select aria-label="Cambiar rol de ' + escapeHtml(user.name) + '" ' +
        (user.id === currentUser.id ? "disabled " : "") +
        'onchange="changeUserRole(\'' + escapeHtml(user.id) + '\', this.value)" ' +
        'class="max-w-[110px] px-2 py-1 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-[10px] ' +
        (user.id === currentUser.id ? "opacity-60 cursor-not-allowed" : "") + '">' + roleOptions + '</select>';

    let statusAction = "";
    if (user.active || user.requestStatus === "aprobado") {
      statusAction = '<span class="text-emerald-600 dark:text-emerald-400">Aprobado</span>';
    } else if (user.requestStatus === "rechazado") {
      statusAction = '<span class="text-rose-600 dark:text-rose-400">Rechazado</span>';
    } else {
      statusAction = '<div class="flex flex-wrap items-center justify-end gap-1.5"><span class="text-amber-600 dark:text-amber-400">Pendiente</span>' +
        '<button type="button" onclick="approveSignup(\'' + escapeHtml(user.id) + '\')" class="px-2 py-1 rounded-md bg-emerald-600 hover:bg-emerald-700 text-white text-[10px] font-semibold">Aprobar</button>' +
        '<button type="button" onclick="rejectSignup(\'' + escapeHtml(user.id) + '\')" class="px-2 py-1 rounded-md bg-rose-600 hover:bg-rose-700 text-white text-[10px] font-semibold">Rechazar</button></div>';
    }

    tr.innerHTML =
      '<td class="py-2.5 px-3 font-medium text-slate-900 dark:text-white">' + escapeHtml(user.name) + '</td>' +
      '<td class="py-2.5 px-3 font-mono text-slate-500 dark:text-slate-400">' + escapeHtml(user.username) + '</td>' +
      '<td class="py-2.5 px-3">' + roleControl + '</td>' +
      '<td class="py-2.5 px-3 text-right text-slate-500">' + statusAction + '</td>';

    tbody.appendChild(tr);
  });

  lucide.createIcons();
}

/* SOLICITUDES PÚBLICAS DE REGISTRO DE MIEMBROS (SOLO ADMIN PARA REVISAR) */
async function loadPendingMemberRequests() {
  if (!currentUser || currentUser.role !== "admin") return;
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
  if (!currentUser || currentUser.role !== "admin") return;
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
  if (!currentUser || currentUser.role !== "admin") return;
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
