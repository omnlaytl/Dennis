// MyVault Web — 核心邏輯（加解密、匯入解析、備份、密碼產生器）
// 不依賴任何第三方套件；可在瀏覽器與 Node 20+ 執行（方便測試）。

const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITERATIONS = 600_000;
export const BACKUP_EXTENSION = 'myvault';

// ───────────────────────── 位元組工具 ─────────────────────────

export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function concatBytes(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromBase64(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ───────────────────────── 加解密 ─────────────────────────
// 格式：iv(12) ‖ 密文 ‖ tag(16)，與 iOS 版 CryptoKit 的 AES.GCM combined 相同

export async function seal(key, bytes) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  return concatBytes(iv, ct);
}

export async function open(key, data) {
  if (data.length < 28) throw new Error('密文長度錯誤');
  const iv = data.slice(0, 12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data.slice(12));
  return new Uint8Array(pt);
}

export async function sealJSON(key, obj) {
  return seal(key, enc.encode(JSON.stringify(obj)));
}

export async function openJSON(key, data) {
  return JSON.parse(dec.decode(await open(key, data)));
}

/** 主密碼 → 金鑰加密金鑰（KEK） */
export async function deriveKeyFromPassword(password, salt, iterations = PBKDF2_ITERATIONS) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']);
}

/** Passkey PRF 輸出 → KEK */
export async function deriveKeyFromPRF(prfOutput, salt) {
  const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('myvault-faceid-kek-v1') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']);
}

/** 隨機產生資料金鑰（DEK），真正用來加密密碼庫 */
export async function generateDataKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function wrapDataKey(kek, dek) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', dek));
  try { return await seal(kek, raw); } finally { raw.fill(0); }
}

export async function unwrapDataKey(kek, wrapped) {
  const raw = await open(kek, wrapped);
  try {
    return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  } finally { raw.fill(0); }
}

// ───────────────────────── 紀錄模型 ─────────────────────────

/** ISO 8601、無毫秒，與 iOS 版 JSONEncoder(.iso8601) 相容 */
export function isoNow(d = new Date()) {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function newId() {
  return crypto.randomUUID ? crypto.randomUUID()
    : Array.from(randomBytes(16), b => b.toString(16).padStart(2, '0')).join('');
}

export function makeRecord(fields = {}) {
  const now = isoNow();
  return {
    id: fields.id || newId(),
    title: fields.title || '',
    username: fields.username || '',
    account: fields.account || '',
    password: fields.password || '',
    url: fields.url || '',
    notes: fields.notes || '',
    category: fields.category || '',
    createdAt: fields.createdAt || now,
    updatedAt: fields.updatedAt || now,
  };
}

export function duplicateKey(r) {
  const who = r.account ? r.account : r.username;
  return `${(r.title || '').trim().toLowerCase()}|${(who || '').trim().toLowerCase()}`;
}

// ───────────────────────── 加密備份（與 iOS 版格式相同） ─────────────────────────
// [ "MYVAULT1"(8) | salt(16) | iterations(4, big-endian) | iv ‖ 密文 ‖ tag ]

const MAGIC = enc.encode('MYVAULT1');

export async function makeBackup(records, password, iterations = PBKDF2_ITERATIONS) {
  const plain = records.map(r => ({
    title: r.title, username: r.username, account: r.account, password: r.password,
    url: r.url, notes: r.notes, category: r.category,
    createdAt: r.createdAt, updatedAt: r.updatedAt,
  }));
  const salt = randomBytes(16);
  const key = await deriveKeyFromPassword(password, salt, iterations);
  const sealed = await seal(key, enc.encode(JSON.stringify(plain)));
  const iter = new Uint8Array(4);
  new DataView(iter.buffer).setUint32(0, iterations, false);
  return concatBytes(MAGIC, salt, iter, sealed);
}

export async function readBackup(bytes, password) {
  const data = new Uint8Array(bytes);
  if (data.length < 8 + 16 + 4 + 28 || !MAGIC.every((b, i) => data[i] === b)) {
    throw new Error('這不是有效的密碼庫備份檔。');
  }
  const salt = data.slice(8, 24);
  const iterations = new DataView(data.buffer, data.byteOffset + 24, 4).getUint32(0, false);
  if (iterations < 10_000 || iterations > 10_000_000) throw new Error('這不是有效的密碼庫備份檔。');
  const key = await deriveKeyFromPassword(password, salt, iterations);
  let json;
  try {
    json = dec.decode(await open(key, data.slice(28)));
  } catch {
    throw new Error('備份密碼錯誤，或檔案已損毀。');
  }
  const list = JSON.parse(json);
  if (!Array.isArray(list)) throw new Error('備份內容格式錯誤。');
  return list.map(r => makeRecord({ ...r, id: undefined }));
}

// ───────────────────────── 密碼產生器 ─────────────────────────

const SETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};
const AMBIGUOUS = new Set('0Oo1lI|');

/** 均勻分布的安全亂數（拒絕取樣，避免取模偏差） */
export function randomInt(n) {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % n;
}

export function generatePassword(opts = {}) {
  const o = { length: 20, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: true, ...opts };
  let sets = Object.keys(SETS).filter(k => o[k]).map(k => [...SETS[k]]);
  if (sets.length === 0) sets = [[...SETS.lower]];
  if (o.avoidAmbiguous) sets = sets.map(s => s.filter(c => !AMBIGUOUS.has(c)));
  const length = Math.max(o.length, sets.length);
  const out = sets.map(s => s[randomInt(s.length)]);   // 每種至少一個
  const all = sets.flat();
  while (out.length < length) out.push(all[randomInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) {             // Fisher–Yates 洗牌
    const j = randomInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join('');
}

/** 粗略估計密碼強度：0 弱 ~ 4 很強 */
export function passwordStrength(pw) {
  if (!pw) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const bits = pw.length * Math.log2(Math.max(pool, 1));
  if (bits < 40) return 0;
  if (bits < 60) return 1;
  if (bits < 80) return 2;
  if (bits < 100) return 3;
  return 4;
}

// ───────────────────────── CSV ─────────────────────────

/** RFC 4180：支援引號、欄位內逗號、換行與 "" 跳脫 */
export function parseCSV(input) {
  let text = input.charCodeAt(0) === 0xFEFF ? input.slice(1) : input;
  const rows = [];
  let row = [], field = '', inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') {
      if (field === '') inQuotes = true; else field += c;
    } else if (c === ',') {
      row.push(field); field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.some(v => v.trim() !== ''));
}

function csvEscape(v) {
  const s = String(v ?? '');
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function makeCSV(header, rows) {
  return [header, ...rows].map(r => r.map(csvEscape).join(',')).join('\r\n') + '\r\n';
}

/** UTF-8 → UTF-16（有 BOM 時）→ Big5（繁中 Windows Excel） */
export function decodeText(bytes) {
  const b = new Uint8Array(bytes);
  if (b[0] === 0xFF && b[1] === 0xFE) return new TextDecoder('utf-16le').decode(b);
  if (b[0] === 0xFE && b[1] === 0xFF) return new TextDecoder('utf-16be').decode(b);
  try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch { /* 不是 UTF-8 */ }
  try { return new TextDecoder('big5').decode(b); } catch { /* 不支援 */ }
  throw new Error('無法辨識檔案編碼，請另存為「CSV UTF-8」。');
}

// ───────────────────────── XLSX（內建輕量解析，免第三方套件） ─────────────────────────

async function inflateRaw(data) {
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** 讀取 ZIP，回傳 { 檔名: Uint8Array } */
export async function unzip(buffer) {
  const data = new Uint8Array(buffer);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let eocd = -1;
  for (let i = data.length - 22; i >= Math.max(0, data.length - 22 - 65535); i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('不是有效的 Excel（.xlsx）檔案。');
  const count = view.getUint16(eocd + 10, true);
  let p = view.getUint32(eocd + 16, true);
  const files = {};
  for (let n = 0; n < count; n++) {
    if (view.getUint32(p, true) !== 0x02014b50) throw new Error('Excel 檔案結構錯誤。');
    const method = view.getUint16(p + 10, true);
    const compSize = view.getUint32(p + 20, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const localOffset = view.getUint32(p + 42, true);
    const name = dec.decode(data.subarray(p + 46, p + 46 + nameLen));
    const lNameLen = view.getUint16(localOffset + 26, true);
    const lExtraLen = view.getUint16(localOffset + 28, true);
    const start = localOffset + 30 + lNameLen + lExtraLen;
    const raw = data.subarray(start, start + compSize);
    if (method === 0) files[name] = raw.slice();
    else if (method === 8) files[name] = await inflateRaw(raw);
    p += 46 + nameLen + extraLen + commentLen;
  }
  return files;
}

function xmlDecode(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&amp;/g, '&')
    .replace(/_x([0-9A-Fa-f]{4})_/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function textOf(xml) {
  // 移除注音／振假名，再串接所有 <t> 內容
  const cleaned = xml.replace(/<rPh\b[\s\S]*?<\/rPh>/g, '');
  let out = '';
  for (const m of cleaned.matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>|<t(?:\s[^>]*)?\/>/g)) out += m[1] ? xmlDecode(m[1]) : '';
  return out;
}

function colIndex(ref) {
  const letters = ref.match(/^[A-Z]+/)[0];
  let n = 0;
  for (const ch of letters) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n - 1;
}

/** 讀取 .xlsx 第一個工作表，回傳二維字串陣列 */
export async function parseXLSX(buffer) {
  const files = await unzip(buffer);
  const str = name => files[name] ? dec.decode(files[name]) : null;

  const shared = [];
  const ss = str('xl/sharedStrings.xml');
  if (ss) for (const m of ss.matchAll(/<si>([\s\S]*?)<\/si>/g)) shared.push(textOf(m[1]));

  let sheetPath = 'xl/worksheets/sheet1.xml';
  const wb = str('xl/workbook.xml');
  const rels = str('xl/_rels/workbook.xml.rels');
  const first = wb && wb.match(/<sheet\b[^>]*\br:id="([^"]+)"/);
  if (first && rels) {
    const rel = [...rels.matchAll(/<Relationship\b[^>]*>/g)].map(m => m[0])
      .find(tag => tag.includes(`Id="${first[1]}"`));
    const target = rel && rel.match(/Target="([^"]+)"/);
    if (target) {
      const t = target[1];
      sheetPath = t.startsWith('/') ? t.slice(1) : 'xl/' + t.replace(/^\.\//, '');
    }
  }
  const sheet = str(sheetPath);
  if (!sheet) throw new Error('找不到工作表。');

  const rows = [];
  for (const rm of sheet.matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
    const row = [];
    let next = 0;
    for (const cm of rm[1].matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
      const attrs = cm[1];
      const body = cm[2] || '';
      const r = attrs.match(/\br="([A-Z]+)\d+"/);
      const idx = r ? colIndex(r[1]) : next;
      const type = (attrs.match(/\bt="([^"]+)"/) || [])[1];
      const v = (body.match(/<v>([\s\S]*?)<\/v>/) || [])[1];
      let value = '';
      if (type === 's') value = shared[parseInt(v, 10)] ?? '';
      else if (type === 'inlineStr') value = textOf(body);
      else if (type === 'b') value = v === '1' ? 'TRUE' : 'FALSE';
      else if (v !== undefined) value = xmlDecode(v);
      while (row.length < idx) row.push('');
      row[idx] = value;
      next = idx + 1;
    }
    rows.push(row);
  }
  return rows.filter(r => r.some(v => String(v).trim() !== ''));
}

// ───────────────────────── 匯入欄位對應 ─────────────────────────

export const FIELDS = [
  { key: 'title', label: '主要名稱', aliases: ['主要名稱', '名稱', '標題', '項目', 'title', 'name'] },
  { key: 'username', label: '使用者名稱', aliases: ['使用者名稱', '使用者', '用戶名', 'username', 'user'] },
  { key: 'account', label: '帳號', aliases: ['帳號', '帳戶', '账号', 'account', 'email', 'login'] },
  { key: 'password', label: '密碼', aliases: ['密碼', 'password', 'pass', 'pwd'] },
  { key: 'url', label: '網址', aliases: ['網頁地址', '網址', '網站', '網頁', 'url', 'website', 'link'] },
  { key: 'notes', label: '備註', aliases: ['備註', '其他備註', '附註', '說明', 'notes', 'note', 'memo'] },
  { key: 'category', label: '分類', aliases: ['分類', '類別', 'category', 'group'] },
];

const norm = s => String(s).toLowerCase().replace(/[\s_　]/g, '').trim();

/** 二維陣列（第一列為標題）→ { records, mapping, unmapped } */
export function rowsToRecords(rows) {
  if (!rows.length) throw new Error('檔案中沒有資料。');
  const header = rows[0].map(h => String(h ?? '').trim());
  const col = {}, mapping = {}, used = new Set();
  for (const f of FIELDS) {
    const aliases = f.aliases.map(norm);
    const idx = header.findIndex((h, i) => !used.has(i) && aliases.includes(norm(h)));
    if (idx >= 0) { col[f.key] = idx; mapping[f.key] = header[idx]; used.add(idx); }
  }
  if (col.title === undefined) {
    throw new Error(`找不到「主要名稱」欄位。目前的欄位標題為：${header.join('、')}`);
  }
  const unmapped = header.map((h, i) => [h, i]).filter(([h, i]) => !used.has(i) && h);

  const records = [];
  for (const row of rows.slice(1)) {
    const raw = k => (col[k] !== undefined && row[col[k]] != null) ? String(row[col[k]]) : '';
    const val = k => raw(k).trim();
    let title = val('title');
    const account = val('account'), username = val('username'), url = val('url');
    if (!title) title = url || account || username;
    if (!title) continue;
    let notes = val('notes');
    for (const [h, i] of unmapped) {
      const extra = String(row[i] ?? '').trim();
      if (extra) notes += (notes ? '\n' : '') + `${h}：${extra}`;
    }
    records.push(makeRecord({
      title, username, account, url, notes,
      password: raw('password'),        // 密碼保留原樣，不修剪空白
      category: val('category'),
    }));
  }
  if (!records.length) throw new Error('檔案中沒有資料。');
  return { records, mapping, unmapped: unmapped.map(([h]) => h) };
}

/** 依副檔名自動判斷 CSV 或 XLSX */
export async function parseImportFile(name, buffer) {
  const lower = name.toLowerCase();
  if (lower.endsWith('.xlsx') || lower.endsWith('.xlsm')) return rowsToRecords(await parseXLSX(buffer));
  if (lower.endsWith('.xls')) throw new Error('不支援舊版 .xls，請在 Excel 另存為 .xlsx 或 CSV UTF-8。');
  return rowsToRecords(parseCSV(decodeText(buffer)));
}

export function recordsToCSV(records) {
  const header = FIELDS.map(f => f.label);
  const rows = records.map(r => FIELDS.map(f => r[f.key] ?? ''));
  return '﻿' + makeCSV(header, rows);
}
