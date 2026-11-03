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

const INITIAL_USERS = [
  {
    id: "u_admin",
    name: "Administrador Principal",
    username: "admin",
    password: "admin123",
    role: "admin"
  }
];

const INITIAL_MEMBERS = [
  {
    id: "1",
    name: "Carlos Eduardo Mendoza",
    phone: "+56 9 8765 4321",
    email: "ejemplo@email.com",
    address: "Av. Las Condes 10000000",
    maritalStatus: "Casado (a)",
    spouseType: "text",
    spouseName: "Elena Ramos",
    spouseId: "",
    ministry: "Alabanza",
    status: "Activo",
    baptized: "Sí",
    birthday: "1990-03-15",
    notes: "Líder de guitarra y apoyo en sonido.",
    avatar: ""
  }
];

const INITIAL_REQUESTS = [
  {
    id: "r1",
    memberId: "1",
    text: "Oración por salud familiar y fortaleza en el trabajo.",
    createdAt: new Date().toISOString()
  },
  {
    id: "r2",
    memberId: "3",
    text: "Petición por exámenes universitarios de fin de semestre.",
    createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString()
  }
];

let users = [];
let currentUser = null;
let members = [];
let prayerRequests = [];
let currentAvatarBase64 = "";

function loadData() {
  const storedUsers = localStorage.getItem('iglesia_renacer_users');
  if (storedUsers) {
    try { users = JSON.parse(storedUsers); } catch(e) { users = INITIAL_USERS; }
  } else {
    users = INITIAL_USERS;
    saveUsers();
  }

  const storedMembers = localStorage.getItem('iglesia_renacer_members');
  if (storedMembers) {
    try { members = JSON.parse(storedMembers); } catch(e) { members = INITIAL_MEMBERS; }
  } else {
    members = INITIAL_MEMBERS;
    saveMembers();
  }

  const storedRequests = localStorage.getItem('iglesia_renacer_requests');
  if (storedRequests) {
    try { prayerRequests = JSON.parse(storedRequests); } catch(e) { prayerRequests = INITIAL_REQUESTS; }
  } else {
    prayerRequests = INITIAL_REQUESTS;
    saveRequests();
  }

  const currentMonth = String(new Date().getMonth() + 1).padStart(2, '0');
  document.getElementById('share-birthday-month').value = currentMonth;

  checkAuth();
}

function saveUsers() {
  localStorage.setItem('iglesia_renacer_users', JSON.stringify(users));
}

function saveMembers() {
  localStorage.setItem('iglesia_renacer_members', JSON.stringify(members));
}

function saveRequests() {
  localStorage.setItem('iglesia_renacer_requests', JSON.stringify(prayerRequests));
}

/* AUTH & PERMISSIONS SYSTEM */
function checkAuth() {
  const storedSession = localStorage.getItem('iglesia_renacer_session');
  if (storedSession) {
    try {
      const user = JSON.parse(storedSession);
      const validUser = users.find(u => u.id === user.id);
      if (validUser) {
        currentUser = validUser;
        showAppView();
        return;
      }
    } catch(e){}
  }
  showLoginView();
}

function handleLogin(e) {
  e.preventDefault();
  const userVal = document.getElementById('login-username').value.trim();
  const passVal = document.getElementById('login-password').value.trim();
  const errorDiv = document.getElementById('login-error');

  const found = users.find(u => u.username.toLowerCase() === userVal.toLowerCase() && u.password === passVal);
  if (found) {
    currentUser = found;
    localStorage.setItem('iglesia_renacer_session', JSON.stringify(found));
    errorDiv.classList.add('hidden');
    showAppView();
  } else {
    errorDiv.classList.remove('hidden');
  }
}

function handleLogout() {
  localStorage.removeItem('iglesia_renacer_session');
  currentUser = null;
  showLoginView();
}

function showLoginView() {
  document.getElementById('login-view').classList.remove('hidden');
  document.getElementById('app-container').classList.add('hidden');
}

function showAppView() {
  document.getElementById('login-view').classList.add('hidden');
  document.getElementById('app-container').classList.remove('hidden');

  document.getElementById('current-user-name').textContent = currentUser.name;
  const badge = document.getElementById('current-user-role-badge');
  badge.textContent = currentUser.role.toUpperCase();

  applyRolePermissions();
  renderDashboard();
  renderTable();
  renderRequests();
  renderBirthdayModule();
}

function applyRolePermissions() {
  const isLectura = currentUser.role === 'lectura';
  const isAdmin = currentUser.role === 'admin';

  const btnAddMember = document.getElementById('btn-add-member');
  const btnAddRequest = document.getElementById('btn-add-request');
  const btnManageUsers = document.getElementById('btn-manage-users');

  if (isLectura) {
    btnAddMember.classList.add('hidden');
    btnAddRequest.classList.add('hidden');
  } else {
    btnAddMember.classList.remove('hidden');
    btnAddRequest.classList.remove('hidden');
  }

  if (isAdmin) {
    btnManageUsers.classList.remove('hidden');
  } else {
    btnManageUsers.classList.add('hidden');
  }
}

/* USER MANAGEMENT (ADMIN ROLE) */
function openUsersModal() {
  if (currentUser.role !== 'admin') return;
  resetUserForm();
  renderUsersTable();
  document.getElementById('users-modal').classList.remove('hidden');
  lucide.createIcons();
}

function closeUsersModal() {
  document.getElementById('users-modal').classList.add('hidden');
}

function resetUserForm() {
  document.getElementById('user-form').reset();
  document.getElementById('user-id').value = '';
  document.getElementById('user-form-title').textContent = 'Crear Nuevo Usuario';
  document.getElementById('user-input-password').required = true;
}

function handleUserSubmit(e) {
  e.preventDefault();
  if (currentUser.role !== 'admin') return;

  const id = document.getElementById('user-id').value;
  const name = document.getElementById('user-input-name').value.trim();
  const username = document.getElementById('user-input-username').value.trim();
  const password = document.getElementById('user-input-password').value.trim();
  const role = document.getElementById('user-input-role').value;

  const existing = users.find(u => u.username.toLowerCase() === username.toLowerCase() && u.id !== id);
  if (existing) {
    alert("El nombre de usuario ya se encuentra registrado.");
    return;
  }

  if (id) {
    const idx = users.findIndex(u => u.id === id);
    if (idx !== -1) {
      users[idx].name = name;
      users[idx].username = username;
      users[idx].role = role;
      if (password) users[idx].password = password;
    }
  } else {
    const newUser = {
      id: 'u_' + Date.now(),
      name,
      username,
      password,
      role
    };
    users.push(newUser);
  }

  saveUsers();
  resetUserForm();
  renderUsersTable();
}

/* IMPORT / EXPORT DATABASE LOGIC */
function exportFullDatabase() {
  if (currentUser.role !== 'admin') return;

  const fullData = {
    app: "Iglesia Renacer - Control Congregacional",
    exportedAt: new Date().toISOString(),
    version: "1.0",
    data: {
      users: users,
      members: members,
      prayerRequests: prayerRequests
    }
  };

  const dateStr = new Date().toISOString().split('T')[0];
  const jsonString = JSON.stringify(fullData, null, 2);
  downloadFile(jsonString, `Iglesia_Renacer_Backup_${dateStr}.json`, 'application/json');
}

function importFullDatabase(event) {
  if (currentUser.role !== 'admin') return;

  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const parsed = JSON.parse(e.target.result);
      
      if (!parsed.data || !Array.isArray(parsed.data.members) || !Array.isArray(parsed.data.users) || !Array.isArray(parsed.data.prayerRequests)) {
        alert("El archivo subido no corresponde a un formato válido de copia de seguridad de Iglesia Renacer.");
        event.target.value = '';
        return;
      }

      const confirmImport = confirm(`¿Estás seguro de restaurar esta copia de seguridad?\n\n- Miembros: ${parsed.data.members.length}\n- Peticiones: ${parsed.data.prayerRequests.length}\n- Usuarios: ${parsed.data.users.length}\n\nNota: Se reemplazarán todos los datos actuales.`);
      
      if (confirmImport) {
        users = parsed.data.users;
        members = parsed.data.members;
        prayerRequests = parsed.data.prayerRequests;

        saveUsers();
        saveMembers();
        saveRequests();

        const activeUserStillExists = users.find(u => u.id === currentUser.id);
        if (!activeUserStillExists) {
          currentUser = users[0] || INITIAL_USERS[0];
          localStorage.setItem('iglesia_renacer_session', JSON.stringify(currentUser));
        }

        renderUsersTable();
        renderDashboard();
        renderTable();
        renderRequests();
        renderBirthdayModule();
        applyRolePermissions();

        alert("¡Base de datos restaurada con éxito!");
      }
    } catch (err) {
      alert("Error al leer el archivo JSON: asegúrate de que sea un archivo de copia de seguridad válido.");
    }
    event.target.value = '';
  };
  reader.readAsText(file);
}

function editUser(id) {
  const u = users.find(usr => usr.id === id);
  if (!u) return;

  document.getElementById('user-id').value = u.id;
  document.getElementById('user-input-name').value = u.name;
  document.getElementById('user-input-username').value = u.username;
  document.getElementById('user-input-password').value = '';
  document.getElementById('user-input-password').required = false;
  document.getElementById('user-input-role').value = u.role;
  document.getElementById('user-form-title').textContent = 'Editar Usuario';
}

function deleteUser(id) {
  if (id === currentUser.id) {
    alert("No puedes eliminar tu propio usuario activo.");
    return;
  }

  if (confirm("¿Estás seguro de eliminar este usuario?")) {
    users = users.filter(u => u.id !== id);
    saveUsers();
    renderUsersTable();
  }
}

function renderUsersTable() {
  const tbody = document.getElementById('users-table-body');
  tbody.innerHTML = '';

  users.forEach(u => {
    const tr = document.createElement('tr');
    tr.className = "hover:bg-slate-50 dark:hover:bg-slate-700/50";

    let roleBadge = "bg-slate-100 text-slate-700 border-slate-300";
    if (u.role === 'admin') roleBadge = "bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-300 border-amber-300";
    if (u.role === 'escritura') roleBadge = "bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 border-blue-300";

    tr.innerHTML = `
      <td class="py-2.5 px-3 font-medium text-slate-900 dark:text-white">${escapeHtml(u.name)}</td>
      <td class="py-2.5 px-3 font-mono text-slate-500 dark:text-slate-400">${escapeHtml(u.username)}</td>
      <td class="py-2.5 px-3">
        <span class="px-2 py-0.5 rounded-md border text-[10px] font-semibold uppercase ${roleBadge}">
          ${escapeHtml(u.role)}
        </span>
      </td>
      <td class="py-2.5 px-3 text-right">
        <button onclick="editUser('${escapeHtml(u.id)}')" title="Editar" class="p-1 text-slate-400 hover:text-blue-600">
          <i data-lucide="edit-3" class="w-3.5 h-3.5"></i>
        </button>
        ${u.id !== currentUser.id ? `
        <button onclick="deleteUser('${escapeHtml(u.id)}')" title="Eliminar" class="p-1 text-slate-400 hover:text-rose-600">
          <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
        </button>` : ''}
      </td>
    `;
    tbody.appendChild(tr);
  });

  lucide.createIcons();
}

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
  if (currentUser.role === 'lectura') return;
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

function handleRequestSubmit(e) {
  e.preventDefault();
  if (currentUser.role === 'lectura') return;

  const memberId = document.getElementById('request-member-select').value;
  const text = document.getElementById('request-description').value.trim();

  const newReq = {
    id: 'r_' + Date.now(),
    memberId: memberId,
    text: text,
    createdAt: new Date().toISOString()
  };

  prayerRequests.unshift(newReq);
  saveRequests();
  renderDashboard();
  renderRequests();
  closeRequestModal();
}

function deleteRequest(id) {
  if (currentUser.role === 'lectura') return;
  if (confirm("¿Estás seguro de eliminar esta petición de oración?")) {
    prayerRequests = prayerRequests.filter(r => r.id !== id);
    saveRequests();
    renderDashboard();
    renderRequests();
  }
}

function handleFormSubmit(e) {
  e.preventDefault();
  if (currentUser.role === 'lectura') return;

  const id = document.getElementById('member-id').value;
  const currentMemberId = id || Date.now().toString();
  const name = document.getElementById('input-name').value.trim();
  const maritalStatus = document.getElementById('input-marital-status').value;
  
  let spouseType = 'none';
  let spouseName = '';
  let spouseId = '';

  if (maritalStatus === 'Casado (a)' || maritalStatus === 'Novio (a)') {
    spouseType = document.querySelector('input[name="spouse_type"]:checked').value;
    if (spouseType === 'link') {
      spouseId = document.getElementById('input-spouse-id').value;
      const foundSpouse = members.find(m => m.id === spouseId);
      spouseName = foundSpouse ? foundSpouse.name : '';
    } else {
      spouseName = document.getElementById('input-spouse-name').value.trim();
    }
  }

  const oldMember = members.find(m => m.id === currentMemberId);
  if (oldMember && oldMember.spouseId && oldMember.spouseId !== spouseId) {
    const oldSpouse = members.find(m => m.id === oldMember.spouseId);
    if (oldSpouse && oldSpouse.spouseId === currentMemberId) {
      oldSpouse.spouseId = '';
      oldSpouse.spouseName = '';
      oldSpouse.spouseType = 'none';
    }
  }

  let avatarToSave = currentAvatarBase64;
  if (!avatarToSave && oldMember) {
    avatarToSave = oldMember.avatar || '';
  }

  const memberData = {
    id: currentMemberId,
    name: name,
    phone: document.getElementById('input-phone').value.trim(),
    email: document.getElementById('input-email').value.trim(),
    address: document.getElementById('input-address').value.trim(),
    maritalStatus: maritalStatus,
    spouseType: spouseType,
    spouseName: spouseName,
    spouseId: spouseId,
    ministry: document.getElementById('input-ministry').value,
    status: document.getElementById('input-status').value,
    baptized: document.getElementById('input-baptized').value,
    birthday: document.getElementById('input-birthday').value,
    notes: document.getElementById('input-notes').value.trim(),
    avatar: avatarToSave
  };

  if (id) {
    const index = members.findIndex(m => m.id === id);
    if (index !== -1) members[index] = memberData;
  } else {
    members.unshift(memberData);
  }

  if ((maritalStatus === 'Casado (a)' || maritalStatus === 'Novio (a)') && spouseType === 'link' && spouseId) {
    const targetSpouse = members.find(m => m.id === spouseId);
    if (targetSpouse) {
      targetSpouse.maritalStatus = maritalStatus;
      targetSpouse.spouseType = 'link';
      targetSpouse.spouseId = currentMemberId;
      targetSpouse.spouseName = name;
    }
  }

  saveMembers();
  renderDashboard();
  renderTable();
  renderBirthdayModule();
  closeModal();
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

function deleteMember(id) {
  if (currentUser.role === 'lectura') return;
  const member = members.find(m => m.id === id);
  if (!member) return;

  const confirmed = window.confirm(`¿Está seguro de eliminar a ${member.name} de los registros?`);
  if (confirmed) {
    if (member.spouseId) {
      const partner = members.find(m => m.id === member.spouseId);
      if (partner && partner.spouseId === id) {
        partner.spouseId = '';
        partner.spouseName = '';
        partner.spouseType = 'none';
      }
    }

    members = members.filter(m => m.id !== id);
    saveMembers();
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

// Inicialización de Event Listeners y estado inicial
document.addEventListener('DOMContentLoaded', function() {
  initTheme();
  loadData();
  
  const formLogin = document.getElementById('form-login');
  if (formLogin) {
    formLogin.addEventListener('submit', handleLogin);
  }

  lucide.createIcons();
});