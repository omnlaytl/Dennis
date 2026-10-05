// MyVault Web — 介面與流程
import * as C from './core.js';

const $ = sel => document.querySelector(sel);
const APP_VERSION = '1.0.0';

// ───────────────────────── DOM 小工具（一律用 textContent，避免 XSS） ─────────────────────────

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6C3.9 8.3 2 12 2 12s3.6 7 10 7a9.6 9.6 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  wand: '<path d="m15 4 1.5 3L20 8.5 16.5 10 15 13l-1.5-3L10 8.5 13.5 7z"/><path d="m3 21 9-9"/>',
  open: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  chev: '<path d="m9 6 6 6-6 6"/>',
};
function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'ico');
  svg.setAttribute('aria-hidden', 'true');
  // ICONS 為程式內固定字串，不含使用者資料
  svg.innerHTML = ICONS[name];
  return svg;
}
function iconBtn(name, label, onclick) {
  return h('button', { class: 'icon-btn', type: 'button', 'aria-label': label, title: label, onclick }, icon(name));
}

// 對話框位於瀏覽器的 top layer，提示與遮罩需用 popover 才能顯示在對話框之上
function raise(el) {
  if (el.showPopover) {
    try { el.hidePopover(); } catch { /* 尚未顯示 */ }
    try { el.showPopover(); } catch { /* 忽略 */ }
  }
  el.hidden = false;
}
function lower(el) {
  if (el.hidePopover) { try { el.hidePopover(); } catch { /* 忽略 */ } }
  el.hidden = true;
}

let toastTimer;
function toast(msg, ms = 2400) {
  const t = $('#toast');
  t.textContent = msg;
  raise(t);
  requestAnimationFrame(() => t.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.classList.remove('show');
    toastTimer = setTimeout(() => lower(t), 250);
  }, ms);
}

async function withBusy(text, fn) {
  const busy = $('#busy');
  $('#busy-text').textContent = text;
  if (!busy.open) busy.showModal();
  // 讓轉圈圈先畫出來，再執行耗時的金鑰衍生
  await new Promise(r => requestAnimationFrame(() => setTimeout(r, 30)));
  try { return await fn(); } finally { busy.close(); }
}

// ───────────────────────── IndexedDB ─────────────────────────

const store = {
  _db: null,
  async db() {
    if (this._db) return this._db;
    this._db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('myvault', 1);
      req.onupgradeneeded = () => req.result.createObjectStore('kv');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return this._db;
  },
  async tx(mode, fn) {
    const db = await this.db();
    return new Promise((resolve, reject) => {
      const t = db.transaction('kv', mode);
      const req = fn(t.objectStore('kv'));
      t.oncomplete = () => resolve(req && req.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  },
  get(k) { return this.tx('readonly', s => s.get(k)); },
  set(k, v) { return this.tx('readwrite', s => s.put(v, k)); },
  clear() { return this.tx('readwrite', s => s.clear()); },
};

// ───────────────────────── 狀態 ─────────────────────────

const state = {
  meta: null,          // { version, pw:{salt,iterations,wrapped}, faceid:{...}|null, settings }
  dek: null,           // 資料金鑰（只存在記憶體）
  records: [],         // 解密後的紀錄（只存在記憶體）
  search: '',
  category: null,
  lastActivity: Date.now(),
  hiddenAt: null,
  externalUI: false,   // 正在使用檔案選擇器、分享表單或 Face ID 時，離開畫面不鎖定
  fidSupported: false,
};

const DEFAULT_SETTINGS = { idleMinutes: 3, awaySeconds: 0, clipboardSeconds: 60 };
const settings = () => ({ ...DEFAULT_SETTINGS, ...(state.meta?.settings || {}) });

async function saveMeta() { await store.set('meta', state.meta); }

async function persist() {
  if (!state.dek) throw new Error('密碼庫已鎖定');
  await store.set('vault', await C.sealJSON(state.dek, state.records));
}

// ───────────────────────── 畫面切換 ─────────────────────────

function showView(id) {
  for (const v of ['setup', 'lock', 'main']) $(`#view-${v}`).hidden = v !== id;
}

function closeDialogs() {
  for (const d of document.querySelectorAll('dialog.sheet[open]')) d.close();
}

async function withExternalUI(fn) {
  state.externalUI = true;
  try { return await fn(); } finally { setTimeout(() => { state.externalUI = false; }, 1500); }
}

async function showLock(message = '') {
  closeDialogs();
  showView('lock');
  $('#lock-pw').value = '';
  $('#lock-error').textContent = message;
  const fid = !!state.meta?.faceid && state.fidSupported;
  $('#btn-faceid').hidden = !fid;
  $('#lock-form button').className = fid ? 'btn block' : 'btn primary block';
}

function lock(reason = '') {
  state.dek = null;
  state.records = [];
  $('#list').replaceChildren();
  if (state.meta) showLock(reason);
}

async function enterVault(dek) {
  const sealed = await store.get('vault');
  state.records = sealed ? await C.openJSON(dek, sealed) : [];
  state.dek = dek;
  state.lastActivity = Date.now();
  state.search = '';
  $('#search').value = '';
  showView('main');
  render();
}

// ───────────────────────── Face ID（WebAuthn Passkey + PRF） ─────────────────────────

async function faceIdSupported() {
  try {
    return !!(window.PublicKeyCredential &&
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch { return false; }
}

async function getPRF(credentialId, prfSalt) {
  const assertion = await withExternalUI(() => navigator.credentials.get({
    publicKey: {
      challenge: C.randomBytes(32),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      userVerification: 'required',
      timeout: 60000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  }));
  const out = assertion?.getClientExtensionResults()?.prf?.results?.first;
  if (!out) throw new Error('此瀏覽器不支援 Face ID 金鑰功能（需要 iOS 18 以上的 Safari）。');
  return new Uint8Array(out);
}

// 注意：Safari 要求 WebAuthn 必須由使用者點擊直接觸發，因此這裡不能先做其他耗時的 await
async function enableFaceID() {
  if (!state.dek) return;
  if (!state.fidSupported) {
    toast('此裝置或瀏覽器不支援 Face ID 解鎖');
    return;
  }
  const prfSalt = C.randomBytes(32);
  const hkdfSalt = C.randomBytes(16);
  const cred = await withExternalUI(() => navigator.credentials.create({
    publicKey: {
      challenge: C.randomBytes(32),
      rp: { name: '密碼庫' },
      user: { id: C.randomBytes(16), name: `密碼庫（${location.hostname}）`, displayName: '密碼庫' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' },
      timeout: 60000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  }));
  const ext = cred.getClientExtensionResults();
  if (!ext.prf || ext.prf.enabled === false) {
    throw new Error('此瀏覽器不支援 Face ID 金鑰功能（需要 iOS 18 以上的 Safari）。請刪除剛建立的通行密鑰，並繼續使用主密碼。');
  }
  const credentialId = new Uint8Array(cred.rawId);
  // 部分瀏覽器建立時就會回傳 PRF 結果；沒有的話再驗證一次
  let out = ext.prf.results?.first ? new Uint8Array(ext.prf.results.first) : null;
  if (!out) {
    const go = await confirmDialog({
      title: '最後一步',
      message: '通行密鑰已建立。請再驗證一次 Face ID 以完成設定。',
      confirm: '驗證 Face ID',
    });
    if (!go) throw new Error('已取消。可稍後在「設定」重新啟用 Face ID。');
    out = await getPRF(credentialId, prfSalt);
  }
  const kek = await C.deriveKeyFromPRF(out, hkdfSalt);
  out.fill(0);
  state.meta.faceid = {
    credentialId, prfSalt, hkdfSalt,
    wrapped: await C.wrapDataKey(kek, state.dek),
    createdAt: C.isoNow(),
  };
  await saveMeta();
  toast('已啟用 Face ID 解鎖');
}

async function unlockWithFaceID() {
  const f = state.meta.faceid;
  const out = await getPRF(f.credentialId, f.prfSalt);
  const kek = await C.deriveKeyFromPRF(out, f.hkdfSalt);
  out.fill(0);
  const dek = await C.unwrapDataKey(kek, f.wrapped);
  await enterVault(dek);
}

async function unlockWithPassword(pw) {
  const p = state.meta.pw;
  const kek = await C.deriveKeyFromPassword(pw, p.salt, p.iterations);
  let dek;
  try { dek = await C.unwrapDataKey(kek, p.wrapped); }
  catch { throw new Error('主密碼錯誤'); }
  await enterVault(dek);
}

/** 敏感操作前再次驗證身分 */
async function reauthenticate(reason) {
  if (state.meta.faceid && state.fidSupported) {
    try {
      const f = state.meta.faceid;
      const out = await getPRF(f.credentialId, f.prfSalt);
      await C.unwrapDataKey(await C.deriveKeyFromPRF(out, f.hkdfSalt), f.wrapped);
      return true;
    } catch { /* 改用主密碼 */ }
  }
  const pw = await promptPassword({ title: '確認身分', message: reason, label: '主密碼', confirm: '確認' });
  if (!pw) return false;
  try {
    const p = state.meta.pw;
    await withBusy('驗證中…', async () =>
      C.unwrapDataKey(await C.deriveKeyFromPassword(pw, p.salt, p.iterations), p.wrapped));
    return true;
  } catch {
    toast('主密碼錯誤');
    return false;
  }
}

// ───────────────────────── 首次設定 ─────────────────────────

async function createVault(pw) {
  const salt = C.randomBytes(16);
  const kek = await C.deriveKeyFromPassword(pw, salt, C.PBKDF2_ITERATIONS);
  const dek = await C.generateDataKey();
  state.meta = {
    version: 1,
    pw: { salt, iterations: C.PBKDF2_ITERATIONS, wrapped: await C.wrapDataKey(kek, dek) },
    faceid: null,
    settings: { ...DEFAULT_SETTINGS },
    createdAt: C.isoNow(),
  };
  state.records = [];
  state.dek = dek;
  await saveMeta();
  await persist();
  try { await navigator.storage?.persist?.(); } catch { /* 忽略 */ }
}

// ───────────────────────── 列表 ─────────────────────────

const AVATAR_COLORS = ['#287ae6', '#7b5be6', '#e2508a', '#e8833a', '#2fa37a', '#2a9cb8', '#c5487b', '#5b6ee6'];
function avatarColor(s) {
  let n = 0;
  for (const ch of s) n = (n * 31 + ch.codePointAt(0)) >>> 0;
  return AVATAR_COLORS[n % AVATAR_COLORS.length];
}

const collator = new Intl.Collator('zh-Hant', { numeric: true, sensitivity: 'base' });

function categories() {
  return [...new Set(state.records.map(r => r.category).filter(Boolean))].sort(collator.compare);
}

function filtered() {
  const q = state.search.trim().toLowerCase();
  return state.records
    .filter(r => !state.category || r.category === state.category)
    .filter(r => !q || [r.title, r.account, r.username, r.url, r.category]
      .some(v => (v || '').toLowerCase().includes(q)))
    .sort((a, b) => collator.compare(a.title, b.title));
}

function render() {
  const cats = categories();
  if (state.category && !cats.includes(state.category)) state.category = null;

  const chips = $('#chips');
  chips.hidden = cats.length === 0;
  chips.replaceChildren(
    ...[null, ...cats].map(c => h('button', {
      class: 'chip', type: 'button', role: 'tab',
      'aria-selected': String(state.category === c),
      onclick: () => { state.category = c; render(); },
    }, c ?? '全部')));

  const items = filtered();
  $('#list').replaceChildren(...items.map(r => {
    const sub = r.account || r.username || r.url;
    const avatar = h('span', { class: 'avatar', 'aria-hidden': 'true' }, [...r.title][0]?.toUpperCase() || '?');
    avatar.style.background = avatarColor(r.title);
    return h('li', {},
      h('button', { class: 'row', type: 'button', onclick: () => openDetail(r.id) },
        avatar,
        h('span', { class: 'row-text' },
          h('div', { class: 'row-title' }, r.title),
          sub ? h('div', { class: 'row-sub' }, sub) : null),
        r.category ? h('span', { class: 'tag' }, r.category) : null,
        h('span', { class: 'chev' }, icon('chev'))));
  }));

  const total = state.records.length;
  $('#empty').hidden = total !== 0;
  $('#count').textContent = total === 0 ? ''
    : items.length === total ? `共 ${total} 筆` : `找到 ${items.length} 筆（共 ${total} 筆）`;
}

// ───────────────────────── 對話框框架 ─────────────────────────

function openSheet({ title, left, right, body, small = false, onClose }) {
  const dlg = small ? $('#dlg2') : $('#dlg');
  const head = h('header', { class: 'sheet-head' },
    h('div', { class: 'left' }, left || null),
    h('h2', {}, title),
    h('div', { class: 'right' }, right || null));
  const content = h('div', { class: 'sheet-body' }, body);
  dlg.replaceChildren(head, content);
  // 前一個對話框的 close 事件可能晚於新內容到達；仍開啟時代表是舊事件，忽略
  dlg.onclose = () => { if (!dlg.open) onClose?.(); };
  if (!dlg.open) dlg.showModal();
  content.scrollTop = 0;
  return dlg;
}

function linkBtn(text, onclick, { bold = false, disabled = false } = {}) {
  return h('button', { class: `link-btn${bold ? ' bold' : ''}`, type: 'button', onclick, disabled }, text);
}

function group(title, ...rows) {
  return [title ? h('p', { class: 'group-title' }, title) : null, h('div', { class: 'group' }, ...rows)];
}

/** 輸入密碼的小對話框，回傳字串或 null */
function promptPassword({ title, message = '', label = '密碼', confirm = '確定', twice = false, minLength = 1 }) {
  return new Promise(resolve => {
    let done = false;
    const finish = v => { if (done) return; done = true; resolve(v); dlg.close(); };
    const a = h('input', { type: 'password', autocomplete: 'off' });
    const b = twice ? h('input', { type: 'password', autocomplete: 'off' }) : null;
    const err = h('p', { class: 'error small' });
    const ok = linkBtn(confirm, () => submit(), { bold: true });
    const submit = () => {
      if (a.value.length < minLength) { err.textContent = `至少需要 ${minLength} 個字元`; return; }
      if (twice && a.value !== b.value) { err.textContent = '兩次輸入不一致'; return; }
      finish(a.value);
    };
    const onKey = e => { if (e.key === 'Enter') { e.preventDefault(); submit(); } };
    a.addEventListener('keydown', onKey);
    b?.addEventListener('keydown', onKey);
    const dlg = openSheet({
      small: true, title,
      left: linkBtn('取消', () => finish(null)),
      right: ok,
      body: [
        message ? h('p', { class: 'muted small' }, message) : null,
        ...group(null,
          h('label', { class: 'field' }, h('span', {}, label), a),
          twice ? h('label', { class: 'field' }, h('span', {}, '再次輸入'), b) : null),
        err,
      ],
      onClose: () => { if (!done) { done = true; resolve(null); } },
    });
    setTimeout(() => a.focus(), 50);
  });
}

function confirmDialog({ title, message, confirm = '確定', danger = false, cancel = confirm === '知道了' ? null : '取消' }) {
  return new Promise(resolve => {
    let done = false;
    const finish = v => { if (done) return; done = true; resolve(v); dlg.close(); };
    const dlg = openSheet({
      small: true, title,
      left: cancel ? linkBtn(cancel, () => finish(false)) : null,
      body: [
        h('p', { class: 'pre-line' }, message),
        h('button', { class: `btn block ${danger ? 'danger solid' : 'primary'}`, type: 'button', onclick: () => finish(true) }, confirm),
      ],
      onClose: () => { if (!done) { done = true; resolve(false); } },
    });
  });
}

// ───────────────────────── 複製 ─────────────────────────

let clipboardTimer;
async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast('無法存取剪貼簿');
    return;
  }
  const secs = settings().clipboardSeconds;
  toast(`已複製${label}，${secs} 秒後嘗試清除`);
  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(async () => {
    try {
      // 瀏覽器限制：只有在頁面仍在前景時才能清除
      if (document.hasFocus()) await navigator.clipboard.writeText('');
    } catch { /* 忽略 */ }
  }, secs * 1000);
}

function safeURL(raw) {
  const s = (raw || '').trim();
  if (!s) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
    return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : null;
  } catch { return null; }
}

// ───────────────────────── 詳細頁 ─────────────────────────

function openDetail(id) {
  const r = state.records.find(x => x.id === id);
  if (!r) return;
  let reveal = false;

  const kv = (label, value, { copy = true, node } = {}) => value ? h('div', { class: 'kv' },
    h('div', { class: 'kv-main' }, h('div', { class: 'kv-label' }, label), node || h('div', { class: 'kv-value' }, value)),
    copy ? iconBtn('copy', `複製${label}`, () => copyText(value, label)) : null) : null;

  const pwValue = h('div', { class: 'kv-value mono' });
  const eyeBtn = iconBtn('eye', '顯示密碼', () => { reveal = !reveal; paintPw(); });
  const paintPw = () => {
    pwValue.textContent = reveal ? r.password : '●'.repeat(Math.min(Math.max(r.password.length, 8), 16));
    eyeBtn.replaceChildren(icon(reveal ? 'eyeOff' : 'eye'));
    eyeBtn.setAttribute('aria-label', reveal ? '隱藏密碼' : '顯示密碼');
  };
  paintPw();

  const url = safeURL(r.url);
  const fmt = iso => { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleString('zh-TW', { dateStyle: 'medium', timeStyle: 'short' }); };

  openSheet({
    title: r.title,
    left: linkBtn('關閉', () => $('#dlg').close()),
    right: linkBtn('編輯', () => openEdit(r.id)),
    body: [
      ...group(null,
        kv('主要名稱', r.title),
        kv('使用者名稱', r.username),
        kv('帳號', r.account),
        r.password ? h('div', { class: 'kv' },
          h('div', { class: 'kv-main' }, h('div', { class: 'kv-label' }, '密碼'), pwValue),
          eyeBtn,
          iconBtn('copy', '複製密碼', () => copyText(r.password, '密碼'))) : null),
      r.url ? group('網址', h('div', { class: 'kv' },
        h('div', { class: 'kv-main' }, url
          ? h('a', { class: 'kv-value', href: url, target: '_blank', rel: 'noopener noreferrer' }, r.url)
          : h('div', { class: 'kv-value' }, r.url)),
        url ? h('a', { class: 'icon-btn', href: url, target: '_blank', rel: 'noopener noreferrer', 'aria-label': '開啟網址' }, icon('open')) : null,
        iconBtn('copy', '複製網址', () => copyText(r.url, '網址')))) : [],
      r.notes ? group('備註', kv('備註', r.notes)) : [],
      r.category ? group('分類', h('div', { class: 'kv' }, h('div', { class: 'kv-value' }, r.category))) : [],
      h('p', { class: 'muted small center-text' }, `建立：${fmt(r.createdAt)}　修改：${fmt(r.updatedAt)}`),
      h('button', {
        class: 'btn danger block', type: 'button',
        onclick: async () => {
          if (await confirmDialog({ title: '刪除項目', message: `確定要刪除「${r.title}」？刪除後無法復原。`, confirm: '刪除', danger: true })) {
            state.records = state.records.filter(x => x.id !== r.id);
            await persist();
            $('#dlg').close();
            render();
            toast('已刪除');
          }
        },
      }, '刪除這筆資料'),
    ],
  });
}

// ───────────────────────── 新增／編輯 ─────────────────────────

function openEdit(id = null) {
  const existing = id ? state.records.find(x => x.id === id) : null;
  const r = existing ? { ...existing } : C.makeRecord();

  const input = (key, attrs = {}) => {
    const el = h('input', { type: 'text', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', ...attrs });
    el.value = r[key] || '';
    el.addEventListener('input', () => { r[key] = el.value; validate(); });
    return el;
  };

  const title = input('title', { placeholder: '必填', autocapitalize: 'sentences' });
  const pw = input('password', { type: 'password', class: 'mono' });
  const meter = h('div', { class: 'strength' }, h('i'), h('i'), h('i'), h('i'));
  const paintMeter = () => meter.dataset.level = r.password ? String(C.passwordStrength(r.password)) : '0';
  pw.addEventListener('input', paintMeter);
  paintMeter();
  let show = false;
  const eye = iconBtn('eye', '顯示密碼', () => {
    show = !show;
    pw.type = show ? 'text' : 'password';
    eye.replaceChildren(icon(show ? 'eyeOff' : 'eye'));
  });
  const gen = iconBtn('wand', '產生密碼', () => openGenerator(v => {
    r.password = v; pw.value = v; show = true; pw.type = 'text';
    eye.replaceChildren(icon('eyeOff')); paintMeter();
  }));

  const cat = input('category', { placeholder: '例如：工作、銀行、社群', autocapitalize: 'sentences' });
  const cats = categories();
  const notes = h('textarea', { rows: '4', placeholder: '其他備註' });
  notes.value = r.notes || '';
  notes.addEventListener('input', () => { r.notes = notes.value; });

  const saveBtn = linkBtn('儲存', async () => {
    r.title = r.title.trim();
    r.url = (r.url || '').trim();
    r.category = (r.category || '').trim();
    r.updatedAt = C.isoNow();
    if (existing) Object.assign(existing, r);
    else state.records.push(r);
    await persist();
    render();
    toast('已儲存');
    if (existing) openDetail(existing.id); else $('#dlg').close();
  }, { bold: true });
  const validate = () => { saveBtn.disabled = !r.title.trim(); };
  validate();

  openSheet({
    title: existing ? '編輯項目' : '新增項目',
    left: linkBtn('取消', () => existing ? openDetail(existing.id) : $('#dlg').close()),
    right: saveBtn,
    body: [
      ...group(null,
        h('label', { class: 'field' }, h('span', {}, '主要名稱'), title),
        h('label', { class: 'field' }, h('span', {}, '使用者名稱'), input('username')),
        h('label', { class: 'field' }, h('span', {}, '帳號'), input('account', { inputmode: 'email' }))),
      ...group('密碼',
        h('div', { class: 'field' }, h('div', { class: 'input-row' }, pw, eye, gen), meter)),
      ...group('網址',
        h('label', { class: 'field' }, input('url', { type: 'url', inputmode: 'url', placeholder: 'https://' }))),
      ...group('分類',
        h('label', { class: 'field' }, cat),
        cats.length ? h('div', { class: 'cat-suggest' }, ...cats.map(c =>
          h('button', { class: 'chip', type: 'button', onclick: () => { cat.value = c; r.category = c; } }, c))) : null),
      ...group('備註', h('label', { class: 'field' }, notes)),
    ],
  });
  if (!existing) setTimeout(() => title.focus(), 80);
}

// ───────────────────────── 密碼產生器 ─────────────────────────

function openGenerator(onUse) {
  const opts = { length: 20, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: true };
  const out = h('div', { class: 'gen-output' });
  const lenLabel = h('span', {});
  const regen = () => { out.textContent = C.generatePassword(opts); lenLabel.textContent = `長度：${opts.length}`; };
  const range = h('input', { type: 'range', min: '8', max: '64', step: '1', value: String(opts.length) });
  range.addEventListener('input', () => { opts.length = +range.value; regen(); });
  const toggle = (key, label) => {
    const cb = h('input', { type: 'checkbox' });
    cb.checked = opts[key];
    cb.addEventListener('change', () => { opts[key] = cb.checked; regen(); });
    return h('label', { class: 'toggle-row' }, h('span', {}, label), cb);
  };
  regen();
  openSheet({
    small: true,
    title: '密碼產生器',
    left: linkBtn('取消', () => $('#dlg2').close()),
    right: onUse
      ? linkBtn('使用', () => { onUse(out.textContent); $('#dlg2').close(); }, { bold: true })
      : linkBtn('複製', () => copyText(out.textContent, '密碼'), { bold: true }),
    body: [
      ...group(null, out, h('button', { class: 'btn block small', type: 'button', onclick: regen }, '重新產生')),
      ...group(null, h('div', { class: 'field' }, lenLabel, range)),
      ...group('字元種類',
        toggle('upper', '大寫字母 A-Z'),
        toggle('lower', '小寫字母 a-z'),
        toggle('digits', '數字 0-9'),
        toggle('symbols', '符號 !@#$'),
        toggle('avoidAmbiguous', '排除易混淆字元（0 O 1 l I）')),
    ],
  });
}

// ───────────────────────── 匯入 ─────────────────────────

function pickFile(input) {
  return withExternalUI(() => new Promise(resolve => {
    input.value = '';
    input.onchange = () => resolve(input.files[0] || null);
    input.oncancel = () => resolve(null);
    input.click();
  }));
}

async function importSpreadsheet() {
  const file = await pickFile($('#file-import'));
  if (!file) return;
  let parsed;
  try {
    parsed = await C.parseImportFile(file.name, await file.arrayBuffer());
  } catch (e) {
    await confirmDialog({ title: '無法匯入', message: e.message, confirm: '知道了' });
    return;
  }
  const existingKeys = new Set(state.records.map(C.duplicateKey));
  const dupCount = parsed.records.filter(r => existingKeys.has(C.duplicateKey(r))).length;
  let strategy = 'skip';

  const seg = h('div', { class: 'segmented' });
  const paintSeg = () => seg.replaceChildren(...[['skip', '略過重複'], ['all', '全部加入']].map(([k, label]) =>
    h('button', { type: 'button', 'aria-pressed': String(strategy === k), onclick: () => { strategy = k; paintSeg(); } }, label)));
  paintSeg();

  openSheet({
    title: '匯入預覽',
    left: linkBtn('取消', () => $('#dlg').close()),
    right: linkBtn('匯入', async () => {
      let added = 0, skipped = 0;
      for (const r of parsed.records) {
        const k = C.duplicateKey(r);
        if (strategy === 'skip' && existingKeys.has(k)) { skipped++; continue; }
        state.records.push(r);
        existingKeys.add(k);
        added++;
      }
      await persist();
      render();
      $('#dlg').close();
      await confirmDialog({
        title: '匯入完成',
        message: `已匯入 ${added} 筆${skipped ? `，略過重複 ${skipped} 筆` : ''}。\n\n請記得刪除原本的 Excel／CSV 檔，避免明文密碼外洩。`,
        confirm: '知道了',
      });
    }, { bold: true }),
    body: [
      ...group(`檔案：${file.name}`,
        h('div', { class: 'kv' }, h('div', { class: 'kv-main' }, '資料筆數'), h('strong', {}, String(parsed.records.length))),
        h('div', { class: 'kv' }, h('div', { class: 'kv-main' }, '與現有資料重複'), h('strong', {}, String(dupCount)))),
      ...group('欄位對應',
        h('table', { class: 'mapping' }, h('tbody', {}, ...C.FIELDS.map(f =>
          h('tr', {}, h('td', {}, f.label), h('td', {}, parsed.mapping[f.key] || '—（未找到）')))))),
      parsed.unmapped.length
        ? h('p', { class: 'group-foot' }, `其他欄位（${parsed.unmapped.join('、')}）會併入備註。`) : null,
      ...group('前 5 筆預覽（不顯示密碼）', ...parsed.records.slice(0, 5).map(r =>
        h('div', { class: 'kv' }, h('div', { class: 'kv-main' },
          h('div', {}, r.title),
          h('div', { class: 'kv-label' }, r.account || r.username || r.url || ''))))),
      ...group('重複資料處理', h('div', { class: 'field' }, seg)),
    ],
  });
}

// ───────────────────────── 檔案輸出（分享表單 → 可存到 Google 雲端硬碟） ─────────────────────────

function offerFile(file, { title, message }) {
  const save = async () => {
    try {
      if (navigator.canShare?.({ files: [file] })) {
        await withExternalUI(() => navigator.share({ files: [file], title: file.name }));
        return;
      }
    } catch (e) {
      if (e.name === 'AbortError') return;
    }
    const url = URL.createObjectURL(file);
    const a = h('a', { href: url, download: file.name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  };
  openSheet({
    small: true, title,
    left: linkBtn('完成', () => $('#dlg2').close()),
    body: [
      h('p', {}, message),
      h('p', { class: 'muted small' }, `檔名：${file.name}`),
      h('button', { class: 'btn primary block', type: 'button', onclick: save }, '儲存／分享檔案'),
      h('p', { class: 'muted small' }, 'iPhone：點按鈕後選「儲存到檔案」，即可存到「Google 雲端硬碟」或 iCloud 雲碟。'),
    ],
  });
}

const stamp = () => {
  const d = new Date(), p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
};

async function exportBackup() {
  const pw = await promptPassword({
    title: '設定備份密碼', twice: true, minLength: 8, confirm: '建立',
    message: '備份檔會用這組密碼加密（至少 8 個字元）。還原時需要輸入，可以和主密碼不同。',
  });
  if (!pw) return;
  const bytes = await withBusy('加密中…', () => C.makeBackup(state.records, pw));
  const file = new File([bytes], `MyVault-backup-${stamp()}.${C.BACKUP_EXTENSION}`, { type: 'application/octet-stream' });
  state.meta.settings = { ...settings(), lastBackupAt: C.isoNow() };
  await saveMeta();
  offerFile(file, { title: '備份已建立', message: `已加密 ${state.records.length} 筆資料。` });
}

async function restoreBackup() {
  const file = await pickFile($('#file-backup'));
  if (!file) return;
  const pw = await promptPassword({ title: '輸入備份密碼', message: `檔案：${file.name}`, label: '備份密碼', confirm: '還原' });
  if (!pw) return;
  try {
    const records = await withBusy('解密中…', async () => C.readBackup(await file.arrayBuffer(), pw));
    const keys = new Set(state.records.map(C.duplicateKey));
    let added = 0, skipped = 0;
    for (const r of records) {
      const k = C.duplicateKey(r);
      if (keys.has(k)) { skipped++; continue; }
      state.records.push(r); keys.add(k); added++;
    }
    await persist();
    render();
    toast(`已還原 ${added} 筆${skipped ? `，略過重複 ${skipped} 筆` : ''}`, 3500);
  } catch (e) {
    await confirmDialog({ title: '還原失敗', message: e.message, confirm: '知道了' });
  }
}

async function exportCSV() {
  if (!await reauthenticate('匯出明文 CSV 前請確認身分')) return;
  const ok = await confirmDialog({
    title: '匯出明文 CSV',
    message: 'CSV 檔中的密碼不會加密，任何人取得檔案都能看到。僅在轉移到其他工具時使用，用完請立即刪除。',
    confirm: '我了解，匯出', danger: true,
  });
  if (!ok) return;
  const file = new File([C.recordsToCSV(state.records)], `MyVault-${stamp()}.csv`, { type: 'text/csv' });
  offerFile(file, { title: '明文 CSV', message: '⚠ 此檔案未加密，請妥善保管並盡快刪除。' });
}

// ───────────────────────── 設定 ─────────────────────────

async function openSettings() {
  const s = settings();
  const fidSupported = state.fidSupported;
  const select = (key, options) => {
    const el = h('select', {}, ...options.map(([v, label]) => {
      const o = h('option', { value: String(v) }, label);
      if (s[key] === v) o.selected = true;
      return o;
    }));
    el.addEventListener('change', async () => {
      state.meta.settings = { ...settings(), [key]: Number(el.value) };
      await saveMeta();
      toast('已更新設定');
    });
    return el;
  };
  const lastBackup = s.lastBackupAt ? new Date(s.lastBackupAt).toLocaleString('zh-TW', { dateStyle: 'medium', timeStyle: 'short' }) : '尚未備份';

  openSheet({
    title: '設定',
    right: linkBtn('完成', () => $('#dlg').close(), { bold: true }),
    body: [
      ...group('解鎖',
        state.meta.faceid
          ? h('button', {
            class: 'list-btn danger', type: 'button',
            onclick: async () => {
              if (await confirmDialog({ title: '停用 Face ID', message: '停用後只能用主密碼解鎖。iPhone「設定 → 密碼」中的通行密鑰可以另外手動刪除。', confirm: '停用', danger: true })) {
                state.meta.faceid = null; await saveMeta(); openSettings(); toast('已停用 Face ID');
              }
            },
          }, '停用 Face ID 解鎖')
          : h('button', {
            class: 'list-btn', type: 'button', disabled: !fidSupported,
            onclick: async () => { try { await enableFaceID(); openSettings(); } catch (e) { if (e.name !== 'NotAllowedError') confirmDialog({ title: '無法啟用', message: e.message, confirm: '知道了' }); } },
          }, fidSupported ? '啟用 Face ID 解鎖' : 'Face ID 解鎖（此瀏覽器不支援）'),
        h('button', { class: 'list-btn', type: 'button', onclick: changeMasterPassword }, '變更主密碼')),
      ...group('自動鎖定',
        h('label', { class: 'field' }, h('span', {}, '閒置多久後鎖定'),
          select('idleMinutes', [[1, '1 分鐘'], [3, '3 分鐘'], [5, '5 分鐘'], [10, '10 分鐘']])),
        h('label', { class: 'field' }, h('span', {}, '離開 App 後'),
          select('awaySeconds', [[0, '立即鎖定'], [30, '30 秒後鎖定'], [60, '1 分鐘後鎖定'], [300, '5 分鐘後鎖定']])),
        h('label', { class: 'field' }, h('span', {}, '複製後清除剪貼簿'),
          select('clipboardSeconds', [[30, '30 秒'], [60, '60 秒'], [120, '2 分鐘']]))),
      ...group('匯入',
        h('button', { class: 'list-btn', type: 'button', onclick: importSpreadsheet }, '從 Excel／CSV 匯入')),
      ...group('備份與還原',
        h('button', { class: 'list-btn', type: 'button', onclick: exportBackup, disabled: !state.records.length }, '匯出加密備份'),
        h('button', { class: 'list-btn', type: 'button', onclick: restoreBackup }, '從加密備份還原')),
      h('p', { class: 'group-foot' }, `上次備份：${lastBackup}。備份檔可存到 Google 雲端硬碟，也能在 iOS 版 MyVault App 還原。`),
      ...group('工具',
        h('button', { class: 'list-btn', type: 'button', onclick: () => openGenerator(null) }, '密碼產生器'),
        h('button', { class: 'list-btn danger', type: 'button', onclick: exportCSV, disabled: !state.records.length }, '匯出明文 CSV')),
      ...group('資訊',
        h('div', { class: 'kv' }, h('div', { class: 'kv-main' }, '資料筆數'), h('span', { class: 'muted' }, String(state.records.length))),
        h('div', { class: 'kv' }, h('div', { class: 'kv-main' }, '加密方式'), h('span', { class: 'muted' }, 'AES-256-GCM')),
        h('div', { class: 'kv' }, h('div', { class: 'kv-main' }, '版本'), h('span', { class: 'muted' }, APP_VERSION))),
      ...group(null,
        h('button', { class: 'list-btn danger', type: 'button', onclick: wipeAll }, '清除此裝置上的所有資料')),
    ],
  });
}

async function changeMasterPassword() {
  if (!await reauthenticate('變更主密碼前請確認身分')) return;
  const pw = await promptPassword({ title: '新的主密碼', twice: true, minLength: 10, confirm: '變更', message: '至少 10 個字元。' });
  if (!pw) return;
  await withBusy('更新中…', async () => {
    const salt = C.randomBytes(16);
    const kek = await C.deriveKeyFromPassword(pw, salt, C.PBKDF2_ITERATIONS);
    state.meta.pw = { salt, iterations: C.PBKDF2_ITERATIONS, wrapped: await C.wrapDataKey(kek, state.dek) };
    await saveMeta();
  });
  toast('已變更主密碼');
}

async function wipeAll() {
  const typed = await promptPassword({
    title: '清除所有資料',
    message: '這會永久刪除此裝置上的所有密碼與設定，無法復原。若要繼續，請輸入「刪除」。',
    label: '輸入「刪除」', confirm: '清除',
  });
  if (typed !== '刪除') { if (typed) toast('輸入不正確，已取消'); return; }
  await store.clear();
  state.meta = null;
  lock();
  location.reload();
}

// ───────────────────────── 自動鎖定與隱私遮罩 ─────────────────────────

function markActivity() { state.lastActivity = Date.now(); }
for (const ev of ['pointerdown', 'keydown', 'touchmove', 'wheel']) {
  window.addEventListener(ev, markActivity, { passive: true, capture: true });
}
setInterval(() => {
  if (state.dek && Date.now() - state.lastActivity >= settings().idleMinutes * 60000) {
    lock('閒置過久，已自動鎖定');
  }
}, 5000);

document.addEventListener('visibilitychange', () => {
  if (state.externalUI) return;   // 檔案選擇器／分享表單／Face ID 視窗
  if (document.hidden) {
    raise($('#cover'));
    state.hiddenAt = Date.now();
    if (state.dek && settings().awaySeconds === 0) lock();
  } else {
    if (state.dek && state.hiddenAt && Date.now() - state.hiddenAt >= settings().awaySeconds * 1000) lock();
    state.hiddenAt = null;
    lower($('#cover'));
  }
});
window.addEventListener('pagehide', () => { if (state.dek && !state.externalUI) lock(); });

// ───────────────────────── 事件綁定 ─────────────────────────

function bind() {
  const setupPw = $('#setup-pw');
  setupPw.addEventListener('input', () => {
    $('#setup-strength').dataset.level = setupPw.value ? String(Math.max(1, C.passwordStrength(setupPw.value))) : '0';
  });
  $('#setup-form').addEventListener('submit', async e => {
    e.preventDefault();
    const a = setupPw.value, b = $('#setup-pw2').value;
    if (a.length < 10) return toast('主密碼至少需要 10 個字元');
    if (a !== b) return toast('兩次輸入不一致');
    await withBusy('建立加密金鑰…', () => createVault(a));
    setupPw.value = $('#setup-pw2').value = '';
    showView('main');
    render();
    if (state.fidSupported) {
      const yes = await confirmDialog({
        title: '啟用 Face ID？',
        message: '啟用後可以用 Face ID 快速解鎖，主密碼仍可作為備用。',
        confirm: '啟用 Face ID',
      });
      if (yes) {
        try { await enableFaceID(); } catch (err) {
          if (err.name !== 'NotAllowedError') await confirmDialog({ title: '無法啟用', message: err.message, confirm: '知道了' });
        }
      }
    }
  });

  $('#lock-form').addEventListener('submit', async e => {
    e.preventDefault();
    const pw = $('#lock-pw').value;
    if (!pw) return;
    $('#lock-error').textContent = '';
    try {
      await withBusy('解鎖中…', () => unlockWithPassword(pw));
    } catch (err) {
      $('#lock-error').textContent = err.message;
      $('#lock-pw').select();
    }
  });

  $('#btn-faceid').addEventListener('click', async () => {
    $('#lock-error').textContent = '';
    try {
      await unlockWithFaceID();
    } catch (err) {
      $('#lock-error').textContent = err.name === 'NotAllowedError'
        ? 'Face ID 已取消，或驗證失敗。'
        : `Face ID 無法使用：${err.message}。請改用主密碼。`;
    }
  });

  $('#btn-add').addEventListener('click', () => openEdit());
  $('#btn-settings').addEventListener('click', openSettings);
  $('#btn-lock').addEventListener('click', () => lock());
  $('#btn-empty-import').addEventListener('click', importSpreadsheet);
  $('#search').addEventListener('input', e => { state.search = e.target.value; render(); });

  // 點擊對話框外的遮罩處關閉；處理中視窗不可用 Esc 關閉
  $('#busy').addEventListener('cancel', e => e.preventDefault());
  for (const d of document.querySelectorAll('dialog.sheet')) {
    d.addEventListener('click', e => { if (e.target === d) d.close(); });
  }
}

// ───────────────────────── Service Worker（離線使用） ─────────────────────────

function registerSW() {
  if (!('serviceWorker' in navigator) || location.protocol !== 'https:') return;
  navigator.serviceWorker.register('sw.js').then(reg => {
    reg.addEventListener('updatefound', () => {
      const nw = reg.installing;
      nw?.addEventListener('statechange', () => {
        if (nw.state === 'installed' && navigator.serviceWorker.controller) {
          toast('已下載新版本，下次開啟時生效', 4000);
        }
      });
    });
  }).catch(() => { /* 忽略 */ });
}

// ───────────────────────── 啟動 ─────────────────────────

async function init() {
  bind();
  registerSW();
  if (!window.isSecureContext || !crypto.subtle) {
    document.body.replaceChildren(h('div', { class: 'view center' },
      h('div', { class: 'card narrow' }, h('h1', {}, '無法啟動'),
        h('p', {}, '此 App 必須透過 HTTPS 開啟，才能使用加密功能。'))));
    return;
  }
  state.fidSupported = await faceIdSupported();
  try {
    state.meta = await store.get('meta');
  } catch (e) {
    toast(`無法存取本機儲存空間：${e.message}`, 6000);
  }
  if (state.meta) showLock(); else showView('setup');
}

init();
