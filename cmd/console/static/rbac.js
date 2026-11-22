// RBAC front-end: loads the operator's permissions, hides actions the role
// cannot perform (the server enforces them regardless) and renders the admin
// "Role" tab (custom roles, user assignment, change audit).
const rbac = {perms: new Set(), role: '', label: '', roles: [], catalog: []};
const can = p => rbac.perms.has(p);

// Controls (matched by their handler) that need a permission.
const RBAC_GUARDS = [
  ['cases:update', '[onclick*="setStatus("],[onclick*="addNote("],[onclick*="runAction("],[onclick*="runAnalysis("],[onclick*="runOperator("],#noteText,.note-box,.status-grid,.actions'],
  ['rules:write', '[onclick*="addRule("],[onclick*="saveRules("],[onclick*="applyRulesNow("],[onclick*="delRule("],[onclick*="moveRule("]'],
  ['config:write', '[onclick*="saveConfig("],[onclick*="saveAiConfig("],[onclick*="saveGtConfig("],[onclick*="toggleAdmin("],[onclick*="deleteUser("]'],
  ['groundtruth:run', '[onclick*="runGroundTruth("]'],
];

async function rbacInit() {
  try {
    const me = await api('/api/rbac/me');
    rbac.perms = new Set(me.permissions); rbac.role = me.role; rbac.label = me.role_label;
  } catch (e) { rbac.perms = new Set(); }
  document.getElementById('rbacBadge')?.remove();
  const tab = document.getElementById('tabRole');
  if (tab) tab.hidden = !can('roles:manage');
  const st = document.querySelector('[data-nav="ustawienia"]');
  if (st) st.hidden = !can('config:read');
  const nm = document.getElementById('userName');
  if (nm && rbac.label) nm.title = 'Rola: ' + rbac.label;
  rbacApply();
  if (!rbac.observer) {
    rbac.observer = new MutationObserver(rbacApply);
    rbac.observer.observe(document.getElementById('app'), {childList: true, subtree: true});
  }
}

function rbacApply() {
  for (const [perm, sel] of RBAC_GUARDS) {
    if (can(perm)) continue;
    document.querySelectorAll('#app ' + sel.split(',').join(', #app ')).forEach(el => {
      if (el.style.display !== 'none') el.style.display = 'none';
    });
  }
  if (!document.getElementById('rbacBadge') && rbac.label) {
    const nm = document.getElementById('userName');
    if (nm) nm.insertAdjacentHTML('afterend', ` <span id="rbacBadge" class="pill">${esc(rbac.label)}</span>`);
  }
}

async function viewRoles() {
  const app = $('#app');
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.nav === 'role'));
  if (!can('roles:manage')) { app.innerHTML = '<div class="panel" style="padding:24px;margin-top:16px"><p class="muted">Brak uprawnień do zarządzania rolami.</p></div>'; return; }
  const [r, u, au] = await Promise.all([api('/api/roles'), api('/api/rbac/users'), api('/api/audit?limit=50').catch(() => ({items: []}))]);
  rbac.roles = r.roles; rbac.catalog = r.permissions;
  const roleOpts = sel => rbac.roles.map(x => `<option value="${esc(x.name)}" ${x.name === sel ? 'selected' : ''}>${esc(x.label)} (${esc(x.name)})</option>`).join('');
  app.innerHTML = `
  <div class="panel" style="margin-top:16px"><h4>OPERATORZY I ROLE</h4>
    ${u.items.map(x => `<div class="setting-row" style="display:flex;gap:12px;align-items:center;padding:6px 0">
      <div style="flex:1"><b>${esc(x.name)}</b> <span class="muted">${esc(x.login)}</span></div>
      <select onchange="rbacSetRole('${esc(x.login)}', this.value)">${roleOpts(x.role)}</select></div>`).join('')}
  </div>
  <div class="panel" style="margin-top:16px"><h4>ROLE</h4>
    ${rbac.roles.map(x => `<div style="border-top:1px solid var(--border,#8884);padding:8px 0">
      <b>${esc(x.label)}</b> <span class="muted">${esc(x.name)}${x.builtin ? ' · wbudowana' : ''}</span>
      ${x.builtin ? '' : `<button class="btn" style="float:right;padding:2px 8px" onclick="rbacEditRole('${esc(x.name)}')">edytuj</button><button class="btn danger" style="float:right;padding:2px 8px;margin-right:6px" onclick="rbacDelRole('${esc(x.name)}')">usuń</button>`}
      <div class="muted" style="font-size:12px">${esc(x.description || '')}</div>
      <div style="font-size:12px;margin-top:4px">${x.permissions.map(p => `<code>${esc(p)}</code>`).join(' ')}</div></div>`).join('')}
  </div>
  <div class="panel" style="margin-top:16px"><h4 id="roleFormTitle">NOWA ROLA</h4>
    <input id="rName" placeholder="nazwa (a-z, 0-9, -, _)" style="margin-right:8px">
    <input id="rLabel" placeholder="etykieta" style="margin-right:8px">
    <input id="rDesc" placeholder="opis" style="width:280px">
    <div style="margin:10px 0;display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:4px">
      ${rbac.catalog.map(c => `<label style="font-size:13px"><input type="checkbox" class="rPerm" value="${esc(c.permission)}"> <code>${esc(c.permission)}</code> — ${esc(c.description)}</label>`).join('')}
    </div>
    <button class="btn primary" onclick="rbacSaveRole()">Zapisz rolę</button>
  </div>
  <div class="panel" style="margin-top:16px"><h4>AUDYT ZMIAN (ostatnie 50)</h4>
    <table style="width:100%;font-size:12px"><tbody>${au.items.map(a => `<tr><td>${fmtDateTime(a.at)}</td><td>${esc(a.actor)}</td><td>${esc(a.role)}</td><td><code>${esc(a.method)} ${esc(a.path)}</code></td><td>${a.status}</td></tr>`).join('') || '<tr><td class="muted">brak wpisów</td></tr>'}</tbody></table>
  </div>`;
}

async function rbacSetRole(login, role) {
  try { await post(`/api/users/${encodeURIComponent(login)}/role`, {role}); } catch (e) { alert(e.message); }
  viewRoles();
}
function rbacEditRole(name) {
  const r = rbac.roles.find(x => x.name === name);
  $('#roleFormTitle').textContent = 'EDYCJA ROLI ' + name;
  $('#rName').value = r.name; $('#rName').dataset.edit = '1'; $('#rName').readOnly = true;
  $('#rLabel').value = r.label; $('#rDesc').value = r.description || '';
  document.querySelectorAll('.rPerm').forEach(c => c.checked = r.permissions.includes(c.value));
  window.scrollTo(0, document.body.scrollHeight);
}
async function rbacSaveRole() {
  const edit = $('#rName').dataset.edit === '1', name = $('#rName').value.trim();
  const body = {name, label: $('#rLabel').value, description: $('#rDesc').value, permissions: [...document.querySelectorAll('.rPerm:checked')].map(c => c.value)};
  try {
    if (edit) await api('/api/roles/' + encodeURIComponent(name), {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    else await post('/api/roles', body);
  } catch (e) { alert(e.message); return; }
  viewRoles();
}
async function rbacDelRole(name) {
  if (!confirm('Usunąć rolę ' + name + '?')) return;
  try { await api('/api/roles/' + encodeURIComponent(name), {method: 'DELETE'}); } catch (e) { alert(e.message); }
  viewRoles();
}
