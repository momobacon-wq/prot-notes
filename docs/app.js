(function () {
  'use strict';
  const $ = (s, r) => (r || document).querySelector(s);
  const KEY_STORE = 'pn.key', THEME = 'pn.theme', REL = 'db.json';
  const utf8 = s => new TextEncoder().encode(s);
  const b64dec = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64enc = u => btoa(String.fromCharCode.apply(null, u));
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let DB = null, meta = null;
  const st = { tab: 'list', q: '', sys: '', act: '', eff: '', grade: '' };

  /* ---------- theme ---------- */
  try { const t = localStorage.getItem(THEME); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* private mode */ }
  function toggleTheme() {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light');
    const n = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = n;
    try { localStorage.setItem(THEME, n); } catch (e) { /* ignore */ }
  }

  /* ---------- crypto ---------- */
  async function deriveKey(pass) {
    const km = await crypto.subtle.importKey('raw', utf8(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64dec(meta.kdf.salt), iterations: meta.kdf.iter }, km,
      { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  async function open(key, buf, aad) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.subarray(0, 12), additionalData: utf8(aad) }, key, buf.subarray(12));
  }
  async function checkKey(key) { try { await open(key, b64dec(meta.check), 'check'); return true; } catch (e) { return false; } }
  async function loadDb(key) {
    const r = await fetch('data/' + REL + '.bin?v=' + meta.build, { cache: 'no-cache' });
    if (!r.ok) throw new Error('資料檔讀取失敗');
    const plain = await open(key, new Uint8Array(await r.arrayBuffer()), REL);
    const ab = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
    return JSON.parse(new TextDecoder().decode(ab));
  }

  async function boot() {
    const msg = $('#gateMsg');
    let ready = null;
    $('#gateForm').addEventListener('submit', async ev => {
      ev.preventDefault();
      const pass = $('#pw').value.trim();
      if (!pass || !ready) return;
      $('#go').disabled = true; msg.textContent = '驗證中…';
      try {
        if (!(await ready)) { $('#go').disabled = false; return; }
        const key = await deriveKey(pass);
        if (!(await checkKey(key))) { msg.textContent = '密語不正確。'; $('#go').disabled = false; return; }
        if ($('#remember').checked) { try { localStorage.setItem(KEY_STORE, b64enc(new Uint8Array(await crypto.subtle.exportKey('raw', key)))); } catch (e) { /* ignore */ } }
        await enter(key);
      } catch (e) { msg.textContent = '解密失敗：' + e.message; $('#go').disabled = false; }
    });
    if (!(window.crypto && crypto.subtle && window.DecompressionStream)) { msg.textContent = '瀏覽器過舊或非 https，無法解密。'; return; }
    ready = (async () => {
      try { meta = await (await fetch('data/meta.json', { cache: 'no-cache' })).json(); return true; }
      catch (e) { msg.textContent = '讀不到加密參數，請重新整理。'; return false; }
    })();
    if (!(await ready)) return;
    let stored = null;
    try { stored = localStorage.getItem(KEY_STORE); } catch (e) { /* ignore */ }
    if (stored) {
      try {
        const key = await crypto.subtle.importKey('raw', b64dec(stored), { name: 'AES-GCM' }, true, ['decrypt']);
        if (await checkKey(key)) { await enter(key); return; }
      } catch (e) { /* fall through */ }
      try { localStorage.removeItem(KEY_STORE); } catch (e) { /* ignore */ }
    }
  }
  async function enter(key) {
    DB = await loadDb(key);
    $('#pw').value = '';
    $('#gate').hidden = true; $('#app').hidden = false;
    document.title = DB.title || '查閱站';
    $('#title').textContent = DB.title || '';
    $('#foot').textContent = (DB.built ? '整理日期 ' + DB.built + '。' : '') + (DB.snapshot ? '資料基礎：' + DB.snapshot : '');
    DB.rows.forEach((r, i) => { r._i = i; r._cls = actClass(r.action); r._hay = hay(r); });
    $('#themeBtn').addEventListener('click', toggleTheme);
    $('#lockBtn').addEventListener('click', () => { try { localStorage.removeItem(KEY_STORE); } catch (e) { /* ignore */ } location.reload(); });
    $('.drawer-bg').addEventListener('click', closeDrawer); $('.drawer-x').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });
    window.addEventListener('hashchange', fromHash);
    fromHash();
  }

  /* ---------- helpers ---------- */
  function actClass(a) {
    const m = (DB.ui && DB.ui.cls) || {};
    for (const k in m) if (m[k].indexOf(a) >= 0) return k;
    return 'a-hold';
  }
  function hay(r) {
    const src = (r.sources || []).map(s => [s.path, s.loc, s.quote].join(' ')).join(' ');
    return [r.id, r.system, r.controller, r.name_zh, r.name_en, r.action, r.action_detail, r.trigger, r.setpoint, r.delay, r.voting,
      (r.signals || []).join(' '), r.devices, r.effective_note, r.note, src].join(' ').toLowerCase().replace(/[-_\s]/g, '');
  }
  const norm = s => s.toLowerCase().replace(/[-_\s]/g, '');
  function hl(text, terms) {
    let h = esc(text);
    terms.forEach(t => { if (t.length < 2) return; const re = new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'); h = h.replace(re, m => '<mark>' + m + '</mark>'); });
    return h;
  }
  function fromHash() {
    const p = new URLSearchParams(location.hash.slice(1));
    st.tab = p.get('t') || 'home'; st.q = p.get('q') || ''; st.sys = p.get('s') || ''; st.act = p.get('a') || ''; st.eff = p.get('e') || ''; st.grade = p.get('g') || '';
    render();
    const id = p.get('id'); if (id) { const r = DB.rows.find(x => x.id === id); if (r) openDrawer(r); } else closeDrawer(true);
  }
  function setHash(extra) {
    const p = new URLSearchParams();
    p.set('t', st.tab); if (st.q) p.set('q', st.q); if (st.sys) p.set('s', st.sys); if (st.act) p.set('a', st.act); if (st.eff) p.set('e', st.eff); if (st.grade) p.set('g', st.grade);
    if (extra && extra.id) p.set('id', extra.id);
    history.replaceState(null, '', '#' + p.toString());
  }
  function countBy(rows, f) { const m = new Map(); rows.forEach(r => { const k = f(r) || '（未填）'; m.set(k, (m.get(k) || 0) + 1); }); return m; }

  /* ---------- render ---------- */
  const TABS = [['home', 0], ['list', 1], ['map', 2], ['open', 3], ['gaps', 4], ['about', 5]];
  function render() {
    $('#tabs').innerHTML = TABS.map(t => '<button type="button" data-t="' + t[0] + '" class="' + (st.tab === t[0] ? 'on' : '') + '">' + esc(((DB.ui && DB.ui.tabs) || [])[t[1]] || t[0]) + '</button>').join('');
    $('#tabs').onclick = e => { const b = e.target.closest('button'); if (!b) return; st.tab = b.dataset.t; setHash(); render(); window.scrollTo(0, 0); };
    const v = $('#view');
    if (st.tab === 'list') return renderList(v);
    if (st.tab === 'map') return renderMap(v);
    if (st.tab === 'open') return renderSections(v, DB.open || []);
    if (st.tab === 'gaps') return renderSections(v, DB.gaps || []);
    if (st.tab === 'about') return renderSections(v, DB.about || []);
    renderHome(v);
  }
  function renderSections(v, secs) {
    v.innerHTML = secs.map(s => '<section class="box"><h2>' + esc(s.h) + '</h2>' + (s.p ? '<p>' + esc(s.p) + '</p>' : '') +
      (s.items && s.items.length ? '<ul>' + s.items.map(i => '<li>' + idLink(esc(i)) + '</li>').join('') + '</ul>' : '') + '</section>').join('') || '<p class="muted">（無）</p>';
  }
  const idLink = h => h.replace(/(^|[^A-Za-z0-9])([A-Z]{2,4}-\d{3})(?![0-9])/g, '$1<a href="#t=list&q=$2">$2</a>');
  function renderMap(v) {
    v.innerHTML = (DB.map || []).map(s => '<section class="box"><h2>' + esc(s.h) + '</h2>' + (s.ps || []).map(p => '<p>' + idLink(esc(p)) + '</p>').join('') +
      (s.rows && s.rows.length ? '<div class="scroll"><table class="t map"><thead><tr>' + s.cols.map(c => '<th>' + esc(c) + '</th>').join('') + '</tr></thead><tbody>' +
        s.rows.map(r => '<tr>' + r.map(c => '<td>' + idLink(esc(c)) + '</td>').join('') + '</tr>').join('') + '</tbody></table></div>' : '') + '</section>').join('') || '<p class="muted">（無）</p>';
  }
  function renderHome(v) {
    const rows = DB.rows, bySys = countBy(rows, r => r.system), acts = [...countBy(rows, r => r.action).keys()];
    const eff = rows.filter(r => r.effective === false).length;
    const cl = (DB.ui && DB.ui.cards) || [];
    const card = (n, l) => '<div class="card"><div class="n">' + n + '</div><div class="l">' + esc(l || '') + '</div></div>';
    let h = '<div class="cards">' + card(rows.length, cl[0]) + card(rows.filter(r => r._cls === 'a-trip').length, cl[1]) + card(rows.filter(r => r._cls === 'a-rb').length, cl[2]) +
      card(rows.filter(r => r._cls === 'a-sd').length, cl[3]) + card(eff, cl[4]) + '</div>';
    (DB.summary || []).forEach(s => { h += '<section class="box"><h2>' + esc(s.h) + '</h2>' + (s.p ? '<p>' + esc(s.p) + '</p>' : '') + (s.items ? '<ul>' + s.items.map(i => '<li>' + esc(i) + '</li>').join('') + '</ul>' : '') + '</section>'; });
    h += '<section class="box"><h2>系統 × 動作</h2><div class="scroll"><table class="t"><thead><tr><th>系統</th>' + acts.map(a => '<th class="num">' + esc(a) + '</th>').join('') + '<th class="num">合計</th></tr></thead><tbody>';
    [...bySys.keys()].forEach(s => {
      h += '<tr><td><a href="#t=list&s=' + encodeURIComponent(s) + '">' + esc(s) + '</a></td>' + acts.map(a => { const n = rows.filter(r => r.system === s && r.action === a).length; return '<td class="num">' + (n || '') + '</td>'; }).join('') + '<td class="num">' + bySys.get(s) + '</td></tr>';
    });
    h += '</tbody></table></div></section>';
    v.innerHTML = h;
  }
  function chipRow(label, key, map, cur) {
    return '<div class="chips"><span class="lab">' + label + '</span><button type="button" class="chip ' + (cur ? '' : 'on') + '" data-k="' + key + '" data-v="">全部</button>' +
      [...map.entries()].map(([k, n]) => '<button type="button" class="chip ' + (cur === k ? 'on' : '') + '" data-k="' + key + '" data-v="' + esc(k) + '">' + esc(k) + '<small>' + n + '</small></button>').join('') + '</div>';
  }
  function renderList(v) {
    const rows = DB.rows;
    v.innerHTML = '<div class="tools"><input id="q" class="search" type="search" placeholder="搜尋（空白分隔＝同時符合）" value="' + esc(st.q) + '">' +
      chipRow('系統', 'sys', countBy(rows, r => r.system), st.sys) + chipRow('動作', 'act', countBy(rows, r => r.action), st.act) +
      chipRow('狀態', 'eff', new Map([['有效', rows.filter(r => r.effective !== false).length], ['不動作', rows.filter(r => r.effective === false).length]]), st.eff) +
      chipRow('證據', 'grade', countBy(rows, r => r.grade), st.grade) + '</div><div id="cnt" class="count"></div><div id="list" class="list"></div>';
    const q = $('#q'); let tm = 0;
    q.addEventListener('input', () => { clearTimeout(tm); tm = setTimeout(() => { st.q = q.value; setHash(); fill(); }, 120); });
    v.querySelector('.tools').addEventListener('click', e => { const b = e.target.closest('.chip'); if (!b) return; st[b.dataset.k] = b.dataset.v; setHash(); renderList(v); });
    $('#list').addEventListener('click', e => { const b = e.target.closest('.row'); if (b) { const r = DB.rows[+b.dataset.i]; setHash({ id: r.id }); openDrawer(r); } });
    fill();
  }
  function fill() {
    const terms = st.q.trim().split(/\s+/).filter(Boolean), nt = terms.map(norm);
    const out = DB.rows.filter(r => (!st.sys || r.system === st.sys) && (!st.act || r.action === st.act) && (!st.grade || r.grade === st.grade) &&
      (!st.eff || (st.eff === '不動作') === (r.effective === false)) && nt.every(t => r._hay.includes(t)));
    $('#cnt').textContent = '符合 ' + out.length + ' ／ ' + DB.rows.length + ' 列';
    $('#list').innerHTML = out.slice(0, 400).map(r => '<button type="button" class="row ' + r._cls + (r.effective === false ? ' off' : '') + '" data-i="' + r._i + '">' +
      '<div class="act">' + esc(r.action) + '<span class="sys">' + esc(r.system) + '</span></div><div>' +
      '<h3>' + hl(r.name_zh || r.name_en, terms) + (r.name_zh && r.name_en ? '<span class="en">' + hl(r.name_en, terms) + '</span>' : '') +
      '<span class="badge ' + (r.grade === '定讞' ? 'g1' : '') + '">' + esc(r.grade) + '</span>' + (r.effective === false ? '<span class="badge offb">目前不動作</span>' : '') + '</h3>' +
      '<div class="trg">' + hl(r.trigger, terms) + '</div><div class="kv">' +
      (r.setpoint ? '<span>設定 <b>' + hl(r.setpoint, terms) + '</b></span>' : '') + (r.delay ? '<span>延時 <b>' + hl(r.delay, terms) + '</b></span>' : '') +
      (r.voting ? '<span>表決 <b>' + hl(r.voting, terms) + '</b></span>' : '') + (r.controller ? '<span>' + esc(r.controller) + '</span>' : '') +
      (r.signals && r.signals.length ? '<span class="sig">' + hl(r.signals.slice(0, 4).join(' · '), terms) + (r.signals.length > 4 ? ' …' : '') + '</span>' : '') +
      '</div></div></button>').join('') + (out.length > 400 ? '<p class="muted">只顯示前 400 列，請縮小條件。</p>' : '');
  }
  function openDrawer(r) {
    const dd = (k, val, cls) => val ? '<dt>' + k + '</dt><dd' + (cls ? ' class="' + cls + '"' : '') + '>' + esc(val) + '</dd>' : '';
    $('#drawerBody').innerHTML = '<h2>' + esc(r.name_zh || r.name_en) + '</h2><p class="en">' + esc(r.name_zh ? r.name_en : '') + '</p>' +
      '<span class="badge">' + esc(r.id) + '</span><span class="badge ' + (r.grade === '定讞' ? 'g1' : '') + '">證據：' + esc(r.grade) + '</span>' + (r.effective === false ? '<span class="badge offb">目前不動作</span>' : '') +
      '<dl>' + dd('系統', r.system) + dd('控制器', r.controller) + dd('動作', r.action) + dd('動作細節', r.action_detail) + dd('觸發條件', r.trigger) + dd('設定值', r.setpoint) +
      dd('延時', r.delay) + dd('表決', r.voting) + dd('邏輯訊號', (r.signals || []).join('、'), 'sig') + dd('元件', r.devices) + dd('不動作原因', r.effective_note) + '</dl>' +
      (r.note ? '<div class="note">' + idLink(esc(r.note)) + '</div>' : '') +
      '<h3>出處</h3>' + (r.sources || []).map(s => '<div class="src"><div><b>' + esc(({ xml: '程式', print: '列印圖', pdf: '文件', xlsx: '表格', report: '既有報告' })[s.kind] || s.kind || '') + '</b>' +
        (s.rendered === false ? '<span class="badge">未開圖</span>' : '') + '</div><div class="p">' + esc(s.path) + (s.loc ? '　' + esc(s.loc) : '') + '</div>' + (s.quote ? '<q>' + esc(s.quote) + '</q>' : '') + '</div>').join('');
    $('#drawer').hidden = false; $('.drawer-panel').scrollTop = 0;
  }
  function closeDrawer(silent) { if ($('#drawer').hidden) return; $('#drawer').hidden = true; if (silent !== true) setHash(); }

  boot();
})();
