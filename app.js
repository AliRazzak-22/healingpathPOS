/* ═══════════════════════════════════════════════════════════════════
   نظام مبيعات صيدلية درب الشفاء — النواة البرمجية الكاملة
   البنية: Offline-First (IndexedDB) + مزامنة Firebase + أرشفة ذكية
   ═══════════════════════════════════════════════════════════════════ */
'use strict';

/* ───────────────────────── 1) أدوات عامة ───────────────────────── */
const $  = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}-${Math.random().toString(36).slice(2, 12)}`);
const DEVICE_ID = (() => { let d = localStorage.getItem('ds_device'); if (!d) { d = uid(); localStorage.setItem('ds_device', d); } return d; })();

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'html') el.innerHTML = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (let kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(kid));
  }
  return el;
}
const fmt  = n => (Math.round((+n || 0) * 100) / 100).toLocaleString('en-US');
const num  = v => { const n = parseFloat(v); return isNaN(n) ? 0 : n; };
const DAYS = ['الأحد','الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت'];
const pad2 = n => String(n).padStart(2, '0');
function dateStr(ts = Date.now()) { const d = new Date(ts); return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())}`; }
/* أول يوم وآخر يوم في الشهر الحالي (يُحسب لحظة الضغط) */
function monthRange(d = new Date()) { return [dateStr(new Date(d.getFullYear(), d.getMonth(), 1).getTime()), dateStr(new Date(d.getFullYear(), d.getMonth() + 1, 0).getTime())]; }
function timeStr(ts = Date.now()) { const d = new Date(ts); const h24 = d.getHours(); const h12 = h24 % 12 || 12; return `${pad2(h12)}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())} ${h24 < 12 ? 'صباحاً' : 'مساءً'}`; }
function fmtDate(ts) { if (!ts) return '—'; const d = new Date(ts); return `${pad2(d.getDate())}/${pad2(d.getMonth()+1)}/${d.getFullYear()}`; }
function fmtTime(ts) { return ts ? timeStr(ts).replace(/^(\d{2}:\d{2}):\d{2}( .*)$/, '$1$2') : '—'; }
function dayName(ts = Date.now()) { return DAYS[new Date(ts).getDay()]; }
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cur = () => state.settings.currency || 'د.ع';
/* شارة الشركة المصنعة — تلاصق اسم البراند كنص واحد أينما عُرض */
const coTag = p => p && p.company ? h('small', { class: 'co-tag' }, p.company) : null;

/* ★ عداد تصاعدي/تنازلي ناعم لأرقام المجاميع — يتحرك تدريجياً (خصوصاً عند الخصم) بدل القفز المباشر */
const _animState = new WeakMap();
function animNum(node, val, suffix = '') {
  if (!node) return;
  val = Math.round((+val || 0) * 100) / 100;
  let st = _animState.get(node);
  if (!st) { st = { cur: 0, raf: 0 }; _animState.set(node, st); }
  cancelAnimationFrame(st.raf);
  if (st.cur === val) { node.textContent = fmt(val) + suffix; return; }
  const from = st.cur, diff = val - from, t0 = performance.now(), dur = 750;
  const step = now => {
    const k = Math.min(1, (now - t0) / dur);
    if (k >= 1) { st.cur = val; node.textContent = fmt(val) + suffix; return; }
    const e = k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2; /* easeInOutCubic */
    st.cur = from + diff * e;
    node.textContent = ((Math.round(st.cur) || 0).toLocaleString('en-US')) + suffix;
    st.raf = requestAnimationFrame(step);
  };
  st.raf = requestAnimationFrame(step);
}
const animSpan = (val, suffix = '') => { const s = h('span', {}, fmt(0) + suffix); animNum(s, val, suffix); return s; };

/* ───────────────────────── 1-ب) الأمن: PBKDF2 + حارس التخمين + صور آمنة ───────────────────────── */
const PBKDF2_ITER = 150000; // قوة التجزئة — ارفعها إلى 250000 إن كانت أجهزتك حديثة
const _b64e = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const _b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function pbkdf2(pass, saltB64, iter = PBKDF2_ITER) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(pass)), 'PBKDF2', false, ['deriveBits']);
  return _b64e(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: _b64d(saltB64), iterations: iter }, k, 256));
}
async function setPassword(acc, pass) { // يخزّن بصمة + ملحاً عشوائياً فقط — لا نص صريح أبداً
  acc.passSalt = _b64e(crypto.getRandomValues(new Uint8Array(16)));
  acc.passIter = PBKDF2_ITER;
  acc.passHash = await pbkdf2(pass, acc.passSalt, acc.passIter);
  delete acc.password;
  acc.mustChangePass = false;
}
async function verifyPassword(acc, pass) {
  if (acc.passHash) return (await pbkdf2(pass, acc.passSalt, acc.passIter || PBKDF2_ITER)) === acc.passHash;
  if (acc.password != null) { // حساب قديم بنص صريح: تحقق ثم ترحيل فوري للبصمة
    if (String(pass) !== String(acc.password)) return false;
    await setPassword(acc, pass);
    await save('accounts', acc);
    return true;
  }
  return false;
}
/* حارس التخمين: 5 محاولات فاشلة → قفل مؤقت يتضاعف (30ث ثم 60ث ثم 120ث… بحد أقصى 10 دقائق) */
const loginGuard = {};
const guardWait = id => { const g = loginGuard[id]; return g && g.lockUntil > Date.now() ? Math.ceil((g.lockUntil - Date.now()) / 1000) : 0; };
function guardFail(id) {
  const g = loginGuard[id] = loginGuard[id] || { fails: 0, lockUntil: 0 };
  g.fails++;
  if (g.fails >= 5) g.lockUntil = Date.now() + Math.min(600, 30 * 2 ** (g.fails - 5)) * 1000;
  return guardWait(id);
}
const guardOK = id => { delete loginGuard[id]; };
/* صورة الحساب تُبنى عبر DOM وتُقبل فقط إن كانت data:image حقيقية — يقفل ثغرة XSS في acc.photo */
const SAFE_PHOTO = /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=\s]+$/i;
function avatarNode(acc) {
  const w = document.createElement('span');
  w.style.cssText = 'display:inline-flex;width:100%;height:100%;border-radius:50%;overflow:hidden;align-items:center;justify-content:center;flex:none';
  if (acc && acc.photo && SAFE_PHOTO.test(acc.photo) && acc.photo.length <= 4 * 1024 * 1024) {
    const img = document.createElement('img');
    img.alt = ''; img.draggable = false; img.style.cssText = 'width:100%;height:100%;object-fit:cover';
    img.src = acc.photo; w.append(img);
  } else {
    /* الافتراضي: شعار الصيدلية logo.svg — وإن تعذّر تحميله يسقط على الرسم الطبي القديم */
    const img = document.createElement('img');
    img.alt = ''; img.draggable = false; img.style.cssText = 'width:100%;height:100%;object-fit:cover';
    img.src = 'logo.svg';
    img.onerror = () => { img.remove(); w.innerHTML = avatarSVG(acc && acc.gender); };
    w.append(img);
  }
  return w;
}
function readAvatarFile(fileInp, cb) { // تحقق موحّد لصور الحسابات المرفوعة
  const f = fileInp.files[0]; if (!f) return;
  if (!/^image\/(png|jpe?g|webp|gif)$/i.test(f.type)) return toast('اختر ملف صورة فقط (PNG / JPG / WebP)', 'r');
  if (f.size > 2.5 * 1024 * 1024) return toast('الصورة كبيرة — الحد الأقصى 2.5MB', 'r');
  const r = new FileReader();
  r.onload = () => cb(r.result);
  r.readAsDataURL(f);
}

/* ───────────────────────── 2) الأيقونات SVG ───────────────────────── */
const IC = (p, vb='0 0 24 24') => `<svg class="ic" viewBox="${vb}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const ICONS = {
  print:    IC('<path d="M6 9V3h12v6"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8" rx="1.5"/>'),
  pos:      IC('<circle cx="9" cy="21" r="1.6"/><circle cx="19" cy="21" r="1.6"/><path d="M2.5 3h2l2.6 12.4a2 2 0 0 0 2 1.6h9.7a2 2 0 0 0 2-1.6L22.5 7H6"/>'),
  report:   IC('<path d="M3 3v18h18"/><path d="M7 15l4-5 3.5 3.5L19 8"/><circle cx="19" cy="8" r="1.4" fill="currentColor"/>'),
  store:    IC('<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3.5 8.5L12 13l8.5-4.5M12 13v8"/>'),
  purchase: IC('<path d="M1.5 4h13v12h-13z"/><path d="M14.5 8h4l3.5 4v4h-8"/><circle cx="6" cy="18.5" r="1.8"/><circle cx="17.5" cy="18.5" r="1.8"/>'),
  suppliers:IC('<circle cx="9" cy="8" r="3.4"/><path d="M2.5 20c.7-3.6 3.4-5.5 6.5-5.5s5.8 1.9 6.5 5.5"/><circle cx="17.5" cy="9.5" r="2.6"/><path d="M16 14.6c2.9.3 5 2.1 5.5 5.4"/>'),
  settings: IC('<circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.55-1 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.09a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55h.09a1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.09a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.55 1z"/>'),
  plus:     IC('<path d="M12 5v14M5 12h14"/>'),
  search:   IC('<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>'),
  edit:     IC('<path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5z"/>'),
  trash:    IC('<path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>'),
  eye:      IC('<path d="M1.5 12S5.5 4.5 12 4.5 22.5 12 22.5 12 18.5 19.5 12 19.5 1.5 12 1.5 12z"/><circle cx="12" cy="12" r="3"/>'),
  dollar:   IC('<circle cx="12" cy="12" r="9.5"/><path d="M12 6.5v11M15.5 9c-.7-1-1.9-1.5-3.5-1.5-2 0-3.2 1-3.2 2.5 0 3.5 7 1.7 7 5 0 1.6-1.4 2.5-3.5 2.5-1.8 0-3.1-.7-3.8-1.8"/>'),
  pill:     IC('<rect x="3" y="9" width="18" height="7" rx="3.5" transform="rotate(-45 12 12)"/><path d="M8.5 8.5l7 7"/>'),
  close:    IC('<path d="M18 6L6 18M6 6l12 12"/>'),
  user:     IC('<circle cx="12" cy="8" r="4"/><path d="M4 21c.9-4.4 4.2-6.5 8-6.5s7.1 2.1 8 6.5"/>'),
  logout:   IC('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>'),
  check:    IC('<path d="M20 6L9 17l-5-5"/>'),
  warn:     IC('<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>'),
  camera:   IC('<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>'),
  cash:     IC('<rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="12" cy="12" r="2.6"/><path d="M6 12h.01M18 12h.01"/>'),
  card:     IC('<rect x="2" y="5" width="20" height="14" rx="2.5"/><path d="M2 10h20M6 15h4"/>'),
  clock:    IC('<circle cx="12" cy="12" r="9.5"/><path d="M12 7v5l3.5 2"/>'),
  box:      IC('<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3.5 8.5L12 13l8.5-4.5M12 13v8"/>'),
  star:     IC('<path d="M12 2.5l2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4 6.1 20.5l1.2-6.5L2.5 9.4l6.6-.9z"/>'),
  barcode:  IC('<path d="M3 5v14M7 5v14M10 5v14M13 5v10M16 5v14M19 5v10M21 5v14"/>'),
  refresh:  IC('<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>'),
  download: IC('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>'),
  upload:   IC('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>'),
  lock:     IC('<rect x="4" y="11" width="16" height="10" rx="2.5"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
  history:  IC('<path d="M3 3v5h5"/><path d="M3.05 13a9 9 0 1 0 .5-5L3 8"/><path d="M12 7v5l3.5 2"/>'),
  receipt:  IC('<path d="M5 2h14v20l-2.3-1.5L14.4 22l-2.4-1.5L9.6 22l-2.3-1.5L5 22z"/><path d="M9 7h6M9 11h6M9 15h4"/>'),
  users:    IC('<circle cx="9" cy="8" r="3.4"/><path d="M2.5 20c.7-3.6 3.4-5.5 6.5-5.5s5.8 1.9 6.5 5.5"/><circle cx="17.5" cy="9.5" r="2.6"/><path d="M16 14.6c2.9.3 5 2.1 5.5 5.4"/>'),
};
const icon = n => ICONS[n] || ICONS.box;

/* ───────────────────────── 3) قاعدة البيانات المحلية (IndexedDB) ─────────────────────────
   صخرة صلبة: كل عملية تُحفظ محلياً فوراً قبل أي شيء، والمزامنة لاحقاً.
   معرفات فريدة عالمياً تمنع أي تعارض حتى مع بيع متزامن من جهازين.      */
const DB = (() => {
  const NAME = 'darb_alshifa_db', VER = 3; // v3: + جدول outbox (طابور الرفع المؤجل)
  const STORES = ['accounts','products','sales','purchases','suppliers','payments','customers','settings','meta','outbox'];
  let db = null;
  const wrap = req => new Promise((res, rej) => { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); });
  function open() {
    return new Promise((res, rej) => {
      const r = indexedDB.open(NAME, VER);
      r.onupgradeneeded = e => {
        const d = e.target.result;
        STORES.forEach(s => { if (!d.objectStoreNames.contains(s)) d.createObjectStore(s, { keyPath: 'id' }); });
      };
      r.onsuccess = () => { db = r.result; res(db); };
      r.onerror = () => rej(r.error);
    });
  }
  const store = (s, m = 'readonly') => db.transaction(s, m).objectStore(s);
  return {
    open,
    put:    (s, v)    => wrap(store(s, 'readwrite').put(v)),
    get:    (s, id)   => wrap(store(s).get(id)),
    all:    (s)       => wrap(store(s).getAll()),
    del:    (s, id)   => wrap(store(s, 'readwrite').delete(id)),
    clear:  (s)       => wrap(store(s, 'readwrite').clear()),
    bulk: async (s, arr) => { for (const v of arr) await wrap(store(s, 'readwrite').put(v)); },
  };
})();

/* ───────────────────────── 4) الحالة المركزية ───────────────────────── */
const state = {
  accounts: [], products: [], sales: [], purchases: [],
  suppliers: [], payments: [], customers: [],
  settings: {}, session: null, customerId: null,
};

/* أشهر 30 شركة أدوية في السوق العراقي — تُزرع تلقائياً وتتعلم الشركات الجديدة */
const DEFAULT_COMPANIES = [
  { name: 'بايونير (Pioneer)', country: 'العراق' },
  { name: 'سامراء (SDI)', country: 'العراق' },
  { name: 'أواميديكا (Awamedica)', country: 'العراق' },
  { name: 'الجزيرة (Al-Jazeera)', country: 'العراق' },
  { name: 'هيكما (Hikma)', country: 'الأردن' },
  { name: 'دار الدواء (Dar Al Dawa)', country: 'الأردن' },
  { name: 'جلفار (Julphar)', country: 'الإمارات' },
  { name: 'سبيماكو (SPIMACO)', country: 'السعودية' },
  { name: 'جمجوم (Jamjoom)', country: 'السعودية' },
  { name: 'تبوك (Tabuk)', country: 'السعودية' },
  { name: 'أمون (Amoun)', country: 'مصر' },
  { name: 'إيبيكو (EPICO)', country: 'مصر' },
  { name: 'فاركو (Pharco)', country: 'مصر' },
  { name: 'بيليم (Bilim)', country: 'تركيا' },
  { name: 'عبدي إبراهيم (Abdi Ibrahim)', country: 'تركيا' },
  { name: 'وورلد ميديسن (World Medicine)', country: 'تركيا' },
  { name: 'نوبل (Nobel)', country: 'تركيا' },
  { name: 'مايكرو لابس (Micro Labs)', country: 'الهند' },
  { name: 'براون آند بيرك (Brown & Burk)', country: 'الهند' },
  { name: 'سيبلاز (Cipla)', country: 'الهند' },
  { name: 'أوروبيندو (Aurobindo)', country: 'الهند' },
  { name: 'صن فارما (Sun Pharma)', country: 'الهند' },
  { name: 'زايدوس (Zydus)', country: 'الهند' },
  { name: 'أجنتا (Ajanta)', country: 'الهند' },
  { name: 'ماكليودز (Macleods)', country: 'الهند' },
  { name: 'استرازينيكا (AstraZeneca)', country: 'بريطانيا' },
  { name: 'جلاكسو (GSK)', country: 'بريطانيا' },
  { name: 'سانوفي (Sanofi)', country: 'فرنسا' },
  { name: 'نوفارتس (Novartis)', country: 'سويسرا' },
  { name: 'باير (Bayer)', country: 'ألمانيا' },
];

const DEFAULT_SETTINGS = {
  id: 'app', pharmacyName: 'صيدلية درب الشفاء', profitPct: 30, lowStock: 10,
    currency: 'د.ع', geminiKey: '', unitNames: ['قطعة','باكيت','شريط','كرتون','علبة','قنينة','أمبول','فيال','كيس','لفافة'],
  generatedBarcode: 0,
  printer: { name: '', w: 38, h: 25 }, // ★ طابعة الملصقات: الاسم + الأبعاد بالمم (افتراضي Xprinter 38×25)
  invoicePrinter: { name: '' },        // ★ طابعة فواتير 80مم (فارغ = الطابعة الافتراضية للنظام)
  printInvoice: true,                  // ★ طباعة الفاتورة تلقائياً بعد كل بيع (تُبدَّل من مفتاح نقطة البيع)
  invoiceDesign: null,                 // ★ تصميم الفاتورة من «استوديو التصميم» (فارغ = التصميم الافتراضي)
};
const findAcc  = id => state.accounts.find(a => a.id === id);
const findProd = id => state.products.find(p => p.id === id && !p.deleted);

/* ★ إجراءات المنتج الموحّدة: عرض / تعديل / حذف */
function productActions(p, tab, extra = []) {
  const inCart = tab && (tab.type === 'pos' || tab.type === 'purchase');
  const canDelete = tab && tab.type === 'inventory';
  return h('div', { class: 'row-act' },
    h('button', { class: 'icon-btn view', title: 'تفاصيل وحركة المادة', html: icon('eye'),
      onclick: () => openTab('details', { productId: p.id }) }),
    h('button', { class: 'icon-btn edit', title: 'تعديل المنتج', html: icon('edit'),
      onclick: () => openTab('product', inCart ? { productId: p.id, returnTab: tab.id, editOnly: true } : { productId: p.id }) }),
    canDelete ? h('button', { class: 'icon-btn del', title: 'حذف المنتج من النظام', html: icon('trash'),
      onclick: () => deleteProductEverywhere(p) }) : null,
    extra);
}
function syncProductEverywhere(f) {
  for (const t of tabs) {
    const s = t.state || {};
    if (t.type === 'pos' && Array.isArray(s.cart)) {
      let hit = false;
      s.cart.forEach(it => { if (it.productId !== f.id) return; hit = true;
        it.name = f.brandName; it.unitIdx = Math.min(it.unitIdx, f.units.length - 1);
        it.sale = salePerUnit(f, it.unitIdx); it.cost = costPerUnit(f, it.unitIdx); });
      if (hit) { s.renderCart && s.renderCart(); s.renderTotals && s.renderTotals(); }
    } else if (t.type === 'purchase' && Array.isArray(s.items)) {
      let hit = false;
      s.items.forEach(it => { if (it.productId !== f.id) return; hit = true;
        it.name = f.brandName; it.unitIdx = Math.min(it.unitIdx, f.units.length - 1); });
      if (hit) { s.renderItems && s.renderItems(); s.drawTotals && s.drawTotals(); }
    }
  }
}
async function deleteProductEverywhere(p) {
  const yes = await confirmBox(`حذف «${p.brandName}» من المخزن؟ (تبقى حركاته السابقة محفوظة)`, { danger: true, okLabel: 'حذف' });
  if (!yes) return false;
  p.deleted = true;
  await save('products', p);
  for (const t of tabs) {
    const s = t.state || {};
    if (t.type === 'pos' && Array.isArray(s.cart) && s.cart.some(it => it.productId === p.id)) {
      s.cart = s.cart.filter(it => it.productId !== p.id);
      s.renderCart && s.renderCart(); s.renderTotals && s.renderTotals();
    } else if (t.type === 'purchase' && Array.isArray(s.items) && s.items.some(it => it.productId === p.id)) {
      s.items = s.items.filter(it => it.productId !== p.id);
      s.renderItems && s.renderItems(); s.drawTotals && s.drawTotals();
    }
  }
  renderSideNav(); toast('تم الحذف', 'b');
  return true;
}
const findSup  = id => state.suppliers.find(s => s.id === id);
const findCust = id => state.customers.find(c => c.id === id);
const me = () => findAcc(state.session);

async function save(storeName, obj) {
  obj.updatedAt = Date.now();
  await DB.put(storeName, obj);
  const coll = state[{accounts:'accounts',products:'products',sales:'sales',purchases:'purchases',suppliers:'suppliers',payments:'payments',customers:'customers'}[storeName] || 'settings'];
  if (Array.isArray(coll)) {
    const i = coll.findIndex(x => x.id === obj.id);
    if (i >= 0) coll[i] = obj; else coll.push(obj);
    } else if (storeName === 'settings') state.settings = obj;
  Sync.push(storeName, obj);
  refreshActiveTab(); // تحديث فوري لأي تبويب تقريري مفتوح عند أي حفظ
  return obj;
}

/* ───────────────────────── 5) مزامنة Firebase ─────────────────────────
   تعمل فور وضع إعدادات المشروع في firebase-config.js.
   Firestore Offline Persistence = لا ضياع لأي بيانات حتى مع انقطاع النت.
   المزامنة ثنائية: أي جهازين يبيعان بنفس الثانية تُدمج بياناتهما تلقائياً. */
/* ───────────────────────── 5) مزامنة Firebase (Realtime Database) ─────────────────────────
   نفس نمط نظام التقارير/الأطباء: db.ref(path).set() للحفظ + db.ref(path).on() للمزامنة الحية.
   الطبقة المحلية: كل حفظ يُكتب أولاً في outbox (IndexedDB) ولا يُحذف منه إلا بعد تأكيد السحابة. */
const Sync = {
  COLLECTIONS: ['accounts','products','sales','purchases','suppliers','payments','customers'],
  _n: 0,
  _chain: Promise.resolve(),
  _timeout(label, ms) { return new Promise((_, rej) => setTimeout(() => rej(new Error('timeout:' + label)), ms)); },
  _race(p, label, ms = 20000) { return Promise.race([p, this._timeout(label, ms)]); },
  _q(fn) { return (this._chain = this._chain.then(fn).catch(e => console.warn('sync apply:', e))); },
  _dirty() {
    clearTimeout(this._rt);
    this._rt = setTimeout(() => { refreshActiveTab(); if (!state.session) renderLogin(); }, 150);
  },

  path(store, id) { return store === 'settings' ? 'pos/settings/app' : `pos/${store}/${id}`; },
  /* RTDB.set يرفض undefined → تنظيف عبر JSON. مفتاح Gemini لا يُرفع للسحابة إطلاقاً */
  cloudDoc(store, obj) {
    const d = JSON.parse(JSON.stringify(obj));
    if (store === 'settings') delete d.geminiKey;
    return d;
  },
  /* RTDB لا يحفظ المصفوفات الفارغة ويحوّل بعضها لكائنات → إعادتها لشكلها الأصلي */
  hydrate(store, d) {
    if (!d || typeof d !== 'object') return d;
      const keys = { products: ['barcodes', 'units', 'stockLog'], sales: ['items'], purchases: ['items'], settings: ['unitNames', 'companies', 'drHidden'] }[store] || [];
    keys.forEach(k => {
      if (d[k] == null) d[k] = [];
      else if (!Array.isArray(d[k])) d[k] = Object.values(d[k]);
    });
    return d;
  },

  async init() {
    if (this.ready) { this.flush(); return; }
    if (this._starting) return;
    const cfg = window.FIREBASE_CONFIG;
    if (!cfg || !cfg.apiKey || !cfg.databaseURL) { setSyncUI(false, 'إعدادات Firebase غير مضبوطة — راجع firebase-config.js'); return; }
    this._starting = true;
    try {
      setSyncUI(false, '① تحميل مكتبات Firebase…');
      if (!window.firebase)      await this._race(this.loadScript('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js'), 'sdk');
      if (!firebase.auth)        await this._race(this.loadScript('https://www.gstatic.com/firebasejs/10.12.2/firebase-auth-compat.js'), 'sdk');
      if (!firebase.database)    await this._race(this.loadScript('https://www.gstatic.com/firebasejs/10.12.2/firebase-database-compat.js'), 'sdk');
      if (!firebase.apps.length) firebase.initializeApp(cfg);
      setSyncUI(false, '② تسجيل الدخول المجهول…');
      this.auth = firebase.auth();
      if (!this.auth.currentUser) await this._race(this.auth.signInAnonymously(), 'auth', 25000);
            this.db = firebase.database();
      this.ready = true;
      this.db.ref('.info/connected').on('value', s => {
        if (s.val() === true) { setSyncUI(true); this.flush(); }
        else setSyncUI(false, 'لا اتصال بالسحابة — الحفظ محلي وسيُرفع تلقائياً عند عودة الاتصال');
      });
      if (!this._listening) { this._listening = true; this.listen(); }
      this.flush();
      this.flush();
    } catch (e) {
      console.warn('Firebase sync error:', e);
      setSyncUI(false, syncErrorText(e));
      setTimeout(() => { if (!this.ready) this.init(); }, 15000);
    }
    this._starting = false;
  },
  loadScript(src) { return new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = rej; document.head.append(s); }); },

  /* إرسال مستند واحد: db.ref(path).set(record).then(...) — الحذف من الطابور فقط بعد التأكيد وبشرط أنه لم يُستبدل بنسخة أحدث */
  async send(entry) {
    try {
      await this.db.ref(this.path(entry.store, entry.docId)).set(this.cloudDoc(entry.store, entry.data));
      const cur = await DB.get('outbox', entry.id);
      if (cur && cur.ts === entry.ts && cur.n === entry.n) await DB.del('outbox', entry.id);
    } catch (e) { console.warn('push failed (kept in outbox):', entry.store, e); }
  },
  /* رفع كل المعلَّق بترتيبه الزمني */
  flush() {
    if (!this.ready) return;
    DB.all('outbox').then(q => q.sort((a, b) => a.ts - b.ts).forEach(entry => this.send(entry))).catch(() => {});
  },
  /* كل حفظ يُكتب في الطابور المحلي أولاً (يصمد أمام إغلاق البرنامج بلا نت)، ثم يُرسل فوراً إن كان متصلاً */
  push(storeName, obj) {
    if (storeName === 'meta') return;
    const entry = { id: `${storeName}__${obj.id || 'app'}`, store: storeName, docId: obj.id || 'app', data: obj, ts: Date.now(), n: ++this._n };
    const queued = DB.put('outbox', entry).catch(() => {});
    if (this.ready) queued.then(() => this.send(entry));
  },

  listen() {
    const onErr = coll => err => { console.warn('listen error:', coll, err); setSyncUI(false, syncErrorText(err)); };
    this.COLLECTIONS.forEach(coll => {
      const ref = this.db.ref('pos/' + coll);
      const apply = snap => this._q(async () => {
        const remote = this.hydrate(coll, snap.val());
        if (!remote || !remote.id) return;
        const local = await DB.get(coll, remote.id);
        if (local && (remote.updatedAt || 0) <= (local.updatedAt || 0)) return;
        await DB.put(coll, remote);
        const arr = state[coll], i = arr.findIndex(x => x.id === remote.id);
        if (i >= 0) arr[i] = remote; else arr.push(remote);
        this._dirty();
      });
      ref.on('child_added', apply, onErr(coll));
      ref.on('child_changed', apply, onErr(coll));
    });
    /* مزامنة حية للإعدادات */
    this.db.ref('pos/settings/app').on('value', snap => this._q(async () => {
      const remote = snap.val();
      if (!remote || (remote.updatedAt || 0) <= (state.settings.updatedAt || 0)) return;
      state.settings = { ...state.settings, ...this.hydrate('settings', remote), id: 'app' };
      await DB.put('settings', state.settings);
      renderTopbar(); renderSideNav();
    }), onErr('settings'));
  },

  /* رفع كامل عبر db.ref().update({...}) دفعات متعددة المسارات */
  async uploadAll() {
    if (!this.ready) return { ok: 0, fail: 0, code: 'not-ready' };
    const jobs = [];
    for (const coll of this.COLLECTIONS) for (const d of state[coll]) jobs.push([this.path(coll, d.id), this.cloudDoc(coll, d)]);
    jobs.push([this.path('settings'), this.cloudDoc('settings', state.settings)]);
    let ok = 0, fail = 0, code = '';
    for (let i = 0; i < jobs.length; i += 200) {
      const chunk = jobs.slice(i, i + 200), upd = {};
      chunk.forEach(([p, d]) => { upd[p] = d; });
      try { await this._race(this.db.ref().update(upd), 'upload', 60000); ok += chunk.length; }
      catch (e) { fail += chunk.length; if (!code) { code = e.code || e.message || 'unknown'; console.warn('uploadAll failed:', e); } }
    }
    return { ok, fail, code };
  }
};
function setSyncUI(on, msg) {
  const d = $('#sync-dot'), l = $('#sync-label');
  if (d) d.classList.toggle('on', !!on);
  if (l) l.textContent = on ? 'متصل — مزامنة حية' : (msg || 'وضع محلي');
}
function syncErrorText(e) {
  const c = String((e && e.code) || ''), m = String((e && e.message) || '');
  if (m.startsWith('timeout:sdk'))    return 'تعذّر تحميل مكتبات Firebase — الإنترنت مقطوع أو gstatic محجوب';
  if (m.startsWith('timeout:auth'))   return 'المصادقة علّقت — فعّل Anonymous من Authentication في Console';
  if (m.startsWith('timeout:server')) return 'Realtime Database لا يرد — أنشئها من Console وراجع databaseURL';
  if (m.startsWith('timeout:'))       return 'انتهت مهلة الاتصال بالسحابة — إعادة محاولة…';
  if (/permission[_-]denied/i.test(c + m)) return 'قواعد Realtime Database ترفض الوصول — اجعلها: ".read": "auth != null", ".write": "auth != null"';
  if (c.includes('operation-not-allowed') || c.includes('admin-restricted') || c.includes('configuration-not-found'))
    return 'فعّل Anonymous من Authentication في Console';
  if (c.includes('api-key-not-valid')) return 'apiKey في firebase-config.js لا يطابق المشروع';
  if (!c && m) return 'خطأ تقني: ' + m;
  return 'لا اتصال بالسحابة — إعادة محاولة تلقائية…';
}

/* ───────────────────────── 6) التنبيهات والمودالات ───────────────────────── */
function toast(msg, type = 'g') {
  const icons = { g: 'check', r: 'warn', b: 'refresh' };
  const t = h('div', { class: `toast ${type}` },
    h('span', { class: 'toast-ic', html: icon(icons[type] || 'check') }),
    h('span', { class: 'toast-msg' }, msg),
    h('i', { class: 'toast-bar' }));
  $('#toast-root').append(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 450); }, 3400);
}
function openModal({ title, icon: ic = 'box', body, actions = [], wide = false, xwide = false, onClose = null, noPad = false }) {
  const root = $('#modal-root');
  const overlay = h('div', { class: 'modal-overlay' });
  const box = h('div', { class: `modal-box${wide ? ' wide' : ''}${xwide ? ' xwide' : ''}` });
  const close = () => { overlay.remove(); if (onClose) onClose(); };
  box.append(
    h('div', { class: 'modal-head' },
      h('h3', {}, h('span', { html: icon(ic) }), title),
      h('button', { class: 'modal-close', html: icon('close'), onclick: close })),
    h('div', { class: 'modal-body', style: noPad ? { padding: 0 } : {} }, body),
  );
  if (actions.length) {
    box.append(h('div', { class: 'modal-foot' }, actions.map(a =>
      h('button', { class: `btn ${a.cls || 'n'}${a.big ? ' big' : ''}`, onclick: () => a.onClick && a.onClick(close) },
        a.icon ? h('span', { html: icon(a.icon) }) : null, a.label))));
  }
  overlay.append(box);
  overlay.addEventListener('mousedown', e => { if (e.target === overlay) close(); });
  root.append(overlay);
  return { close, box };
}
function confirmBox(msg, { danger = false, okLabel = 'تأكيد', icon: ic = 'warn' } = {}) {
  return new Promise(res => {
    let settled = false;
    const settle = v => { if (!settled) { settled = true; res(v); } };
    openModal({
      title: 'تأكيد العملية', icon: ic,
      body: h('p', { style: { fontWeight: 800, fontSize: '15px', lineHeight: 2 } }, msg),
      actions: [
        { label: 'إلغاء', cls: 'n', onClick: c => { settle(false); c(); } },
        { label: okLabel, cls: danger ? 'r' : 'g', onClick: c => { settle(true); c(); } },
      ],
      onClose: () => settle(false),
    });
  });
}
function promptBox(title, { placeholder = '', value = '', type = 'text', okLabel = 'حفظ' } = {}) {
  return new Promise(res => {
    let settled = false;
    const settle = v => { if (!settled) { settled = true; res(v); } };
    const inp = h('input', { type, value, placeholder, style: { width: '100%', border: '1.5px solid var(--line)', borderRadius: '12px', padding: '11px 14px', fontWeight: 800, fontSize: '15px', outline: 'none' } });
    const done = (c) => { const v = inp.value.trim(); settle(v || null); c(); };
    openModal({
      title, icon: 'edit', body: inp,
      actions: [{ label: 'إلغاء', cls: 'n', onClick: c => { settle(null); c(); } }, { label: okLabel, cls: 'g', onClick: done }],
      onClose: () => settle(null),
    });
    inp.focus(); inp.select();
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); done(() => $('#modal-root').innerHTML = ''); } });
  });
}

/* ───────────────────────── 7) الصور الرمزية الافتراضية ───────────────────────── */
function avatarSVG(gender) {
  if (gender === 'female') {
    return `<svg viewBox="0 0 100 100"><defs><linearGradient id="avf" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#3b82f6"/><stop offset="1" stop-color="#1d4ed8"/></linearGradient></defs><circle cx="50" cy="50" r="50" fill="#eff6ff"/><path d="M50 18c-14 0-22 10-22 24 0 8 2 14 5 18-1 6-3 10-5 13h44c-2-3-4-7-5-13 3-4 5-10 5-18 0-14-8-24-22-24z" fill="url(#avf)"/><circle cx="50" cy="44" r="14" fill="#fde8d8"/><path d="M36 42c0-10 6-16 14-16s14 6 14 16c0 2 0 4-.6 6 1.4-3 .6-8-1.4-10-1 3-4 5-12 5s-11-2-12-5c-2 2-2.8 7-1.4 10-.6-2-.6-4-.6-6z" fill="url(#avf)"/><path d="M28 78c3-9 12-13 22-13s19 4 22 13v4H28z" fill="#fff"/><path d="M28 78c3-9 12-13 22-13s19 4 22 13" fill="none" stroke="#3b82f6" stroke-width="2"/><rect x="44" y="66" width="12" height="4" rx="2" fill="#3b82f6"/></svg>`;
  }
  return `<svg viewBox="0 0 100 100"><defs><linearGradient id="avm" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#22c55e"/><stop offset="1" stop-color="#15803d"/></linearGradient></defs><circle cx="50" cy="50" r="50" fill="#f0fdf4"/><circle cx="50" cy="42" r="15" fill="#fde8d8"/><path d="M35 40c0-9 7-15 15-15s15 6 15 15c0 1.5-.1 3-.4 4.4.8-3.4.2-8.4-2-10.8-1.2 2.8-4.6 4.4-12.6 4.4s-11.4-1.6-12.6-4.4c-2.2 2.4-2.8 7.4-2 10.8-.3-1.4-.4-2.9-.4-4.4z" fill="#334155"/><path d="M26 80c3-11 13-16 24-16s21 5 24 16v6H26z" fill="#fff"/><path d="M26 80c3-11 13-16 24-16s21 5 24 16" fill="none" stroke="url(#avm)" stroke-width="2.5"/><path d="M40 68l6 6 4-8 4 8 6-6" fill="none" stroke="url(#avm)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><rect x="43" y="64" width="14" height="4" rx="2" fill="url(#avm)"/></svg>`;
}
const PREGNANCY_SVG = `<svg viewBox="0 0 64 64" fill="currentColor"><circle cx="28.5" cy="9" r="6.8"/><ellipse cx="27" cy="30.5" rx="8.8" ry="12"/><circle cx="38.5" cy="36.5" r="8.2"/><path d="M21.5 39.5h6.8v16.8c0 1.7-1.4 3-3.1 3s-3.7-1.3-3.7-3z"/></svg>`;
function accountAvatar(acc, size = 40) {
  const s = avatarNode(acc);
  s.style.width = size + 'px'; s.style.height = size + 'px';
  return s;
}

/* ───────────────────────── 8) شاشة تسجيل الدخول ───────────────────────── */
function renderLogin() {
  const row = $('#accounts-row');
  row.innerHTML = '';
  const accs = state.accounts.filter(a => !a.deleted);
  accs.forEach(acc => {
    const c = h('div', { class: 'acc-circle', onclick: () => openPassword(acc) },
            h('div', { class: 'ring' }, h('div', { class: 'acc-face' }, avatarNode(acc))),
      h('div', { class: 'acc-name' }, acc.name),
      acc.role === 'admin' ? h('div', { class: 'acc-badge' }, 'مدير النظام') : null,
    );
    row.append(c);
  });
  row.append(h('div', { class: 'acc-circle add', onclick: openCreateAccount },
    h('div', { class: 'ring' }, h('div', { class: 'acc-face', html: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" style="width:44px;height:44px"><path d="M12 5v14M5 12h14"/></svg>` })),
    h('div', { class: 'acc-name' }, 'إنشاء حساب')));
  $('#login-pharmacy-name').textContent = state.settings.pharmacyName || 'صيدلية درب الشفاء';
}
function tickLoginClock() {
  const el = $('#login-clock'), d = $('#login-date');
  if (el) el.textContent = `${dayName()} • ${timeStr()}`;
  if (d) d.textContent = fmtDate(Date.now());
}
setInterval(tickLoginClock, 1000);

/* نافذة إنشاء حساب */
function openCreateAccount() {
  let photo = null;
  const nameInp = h('input', { placeholder: 'مثال: أحمد محمد' });
    const passInp = h('input', { type: 'password', placeholder: 'نص أو أرقام — أي طول مسموح', autocomplete: 'new-password', dir: 'ltr' });
  const fileInp = h('input', { type: 'file', accept: 'image/*' });
  const apInner = h('div', { class: 'ap-inner' }, avatarNode(null)); // الافتراضي: شعار الصيدلية
    fileInp.addEventListener('change', () => readAvatarFile(fileInp, data => {
    photo = data; apInner.innerHTML = ''; apInner.append(avatarNode({ photo }));
  }));
  const m = openModal({
    title: 'إنشاء حساب جديد', icon: 'user',
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field' }, h('label', {}, 'اسم الحساب ', h('span', { class: 'req' }, '*')), nameInp),
      h('div', { class: 'f-field' }, h('label', {}, 'كلمة المرور ', h('span', { class: 'req' }, '*')), passInp),
      h('div', { class: 'f-field full' },
        h('label', {}, 'صورة الحساب (اختياري)'),
        h('div', { class: 'avatar-preview' },
          h('div', { class: 'ap-frame' }, apInner,
            h('label', { class: 'ap-edit', html: icon('camera') }, fileInp))),
        h('div', { class: 'f-hint', style: { textAlign: 'center', color: 'var(--faint)', fontSize: '11.5px', fontWeight: 700 } },
          'إذا لم تختر صورة، سيُمنح الحساب شعار الصيدلية تلقائياً')),
    ),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'إنشاء الحساب', cls: 'g', icon: 'check', big: true, onClick: async c => {
                const name = nameInp.value.trim(), pass = passInp.value;
        if (!name) return toast('أدخل اسم الحساب', 'r');
        if (!pass) return toast('أدخل كلمة المرور (حتى حرف واحد يكفي)', 'r');
        if (state.accounts.some(a => !a.deleted && a.name === name)) return toast('يوجد حساب بهذا الاسم مسبقاً', 'r');
        const firstAdmin = !state.accounts.some(a => !a.deleted); // أول حساب بالنظام = مدير تلقائياً
        const acc = { id: uid(), name, photo, role: firstAdmin ? 'admin' : 'staff', createdAt: Date.now() };
        await setPassword(acc, pass); // بصمة PBKDF2 + ملح عشوائي — لا نص صريح
        await save('accounts', acc);
        c(); renderLogin();
        toast(`تم إنشاء حساب «${name}» بنجاح`);
      } },
    ],
  });
}

/* نافذة كلمة المرور — حقل نصي كامل (أحرف/أرقام/رموز وبأي طول حتى حرف واحد) + قفل ضد التخمين */
function openPassword(acc) {
  const lockMsg = h('div', { class: 'lock-msg', style: { display: 'none' } },
    h('span', { html: icon('warn') }), 'محاولات فاشلة كثيرة — الحساب مقفل مؤقتاً، تبقى ', h('b', {}, '0'), ' ثانية');
  const passInp = h('input', { type: 'password', class: 'pass-input', placeholder: 'كلمة المرور', autocomplete: 'current-password', dir: 'ltr' });
  const syncLock = () => {
    const w = guardWait(acc.id);
    lockMsg.style.display = w ? 'flex' : 'none';
    if (w) lockMsg.querySelector('b').textContent = w;
  };
  passInp.addEventListener('input', syncLock);
  let busy = false;
  const enterBtn = h('button', { class: 'btn g big', style: { width: '100%', marginTop: '14px' } }, h('span', { html: icon('check') }), 'دخول');
  const tryLogin = async () => {
    if (busy) return;
    if (guardWait(acc.id)) { syncLock(); return; }
    busy = true; enterBtn.disabled = true;
    try {
      if (await verifyPassword(acc, passInp.value)) {
        guardOK(acc.id); m.close(); await login(acc);
      } else {
        guardFail(acc.id); syncLock();
        passInp.value = ''; passInp.classList.add('err');
        setTimeout(() => passInp.classList.remove('err'), 450);
        if (!guardWait(acc.id)) toast('كلمة المرور غير صحيحة', 'r');
      }
    } finally { busy = false; enterBtn.disabled = false; if (document.body.contains(passInp)) passInp.focus(); }
  };
  enterBtn.addEventListener('click', tryLogin);
  passInp.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); tryLogin(); } });
  const m = openModal({
    title: 'تسجيل الدخول', icon: 'lock',
    body: h('div', { style: { textAlign: 'center' } },
      h('div', { class: 'avatar-preview' }, h('div', { class: 'ap-frame' }, h('div', { class: 'ap-inner' }, avatarNode(acc)))),
      h('h3', { style: { fontWeight: 900, fontSize: '19px' } }, acc.name),
      h('p', { style: { color: 'var(--muted)', fontWeight: 700, fontSize: '13px' } }, 'أدخل كلمة المرور للمتابعة — أي أحرف أو أرقام وبأي طول'),
      h('div', { class: 'pass-row' }, passInp,
        h('button', { class: 'pass-eye', type: 'button', title: 'إظهار / إخفاء', html: icon('eye'),
          onclick: () => { passInp.type = passInp.type === 'password' ? 'text' : 'password'; passInp.focus(); } })),
      lockMsg, enterBtn),
  });
  syncLock();
  setTimeout(() => passInp.focus(), 60);
}
async function login(acc) {
  state.session = acc.id;
  state.customerId = null;
  $('#login-screen').classList.add('hidden');
  const mustChange = acc.mustChangePass;
  $('#app').classList.remove('hidden');
  renderTopbar(); renderSideNav();
  tabs = [];
  openTab('pos');
  toast(`مرحباً بك، ${acc.name}`);
  if (mustChange) setTimeout(() => { openTab('settings'); toast('كلمة مرورك افتراضية ومعروفة — غيّرها الآن من قسم «حسابي»', 'r'); }, 700);
}
function logout() {
  state.session = null;
  $('#app').classList.add('hidden');
  $('#login-screen').classList.remove('hidden');
  $('#content').innerHTML = ''; $('#tabs').innerHTML = '';
  tabs = [];
  renderLogin(); tickLoginClock();
}

/* ───────────────────────── 9) الهيكل: الشريط العلوي + الجانبي ───────────────────────── */
const NAV = [
  { type: 'pos',         label: 'نقطة البيع',      icon: 'pos' },
  { type: 'returnsale',  label: 'إرجاع بيع',       icon: 'refresh' },
  { type: 'sales',       label: 'تقرير المبيعات',   icon: 'report' },
  { type: 'inventory',   label: 'المخزن',           icon: 'store' },
  { type: 'purchase',    label: 'قائمة شراء',       icon: 'purchase' },
  { type: 'returnpurch', label: 'إرجاع شراء',       icon: 'refresh' },
  { type: 'preport',     label: 'تقرير المشتريات',  icon: 'history' },
  { type: 'suppliers',   label: 'حسابات مجهزين',    icon: 'suppliers' },
  { type: 'debts',       label: 'الديون',            icon: 'dollar' },
  { type: 'statement',   label: 'كشف حساب',         icon: 'receipt' },
  { type: 'settings',    label: 'الإعدادات',        icon: 'settings' },
];
function renderTopbar() {
  const acc = me(); if (!acc) return;
  $('#tb-pharmacy-name').textContent = state.settings.pharmacyName;
  const emp = $('#tb-employee');
  emp.innerHTML = '';
    emp.append(accountAvatar(acc, 28), h('b', {}, acc.name),
    acc.role === 'admin' ? h('span', { class: 'badge b' }, 'مدير') : null);
    const lo = $('#btn-logout');
  lo.innerHTML = icon('logout'); lo.onclick = logout;
  $$('.tb-info .win-ctl, .tb-info .theme-sw').forEach(n => n.remove());
  lo.after(themeToggle());
  const wc = winControls(); if (wc) lo.after(wc);
  tickTopClock();
}
function tickTopClock() {
  if (!state.session) return;
  $('#tb-day').textContent = dayName();
  $('#tb-date').textContent = fmtDate(Date.now());
  $('#tb-clock').textContent = timeStr();
}
setInterval(tickTopClock, 1000);
function renderSideNav() {
  const nav = $('#side-nav');
  nav.innerHTML = '';
  const lowCount = state.products.filter(p => !p.deleted && (p.stockBase || 0) <= (state.settings.lowStock ?? 10)).length;
  const debtCount = state.customers.filter(c => !c.deleted && (c.debt || 0) > 0).length;
  NAV.forEach(n => {
        const item = h('div', { class: 'nav-item', dataset: { nav: n.type }, onclick: () => {
      if (n.type === 'pos') { const first = tabs.find(t => t.type === 'pos'); if (first) { activateTab(first.id); return; } } // تنقّل لأول نقطة بيع مفتوحة — التبويب الجديد حصرياً من زر +
      openTab(n.type);
    } },
      h('span', { html: icon(n.icon) }), n.label,
      n.type === 'debts' && debtCount ? h('span', { class: 'nav-count' }, debtCount) : null);
    nav.append(item);
  });
  markActiveNav();
}
function markActiveNav() {
  const act = tabs.find(t => t.id === activeTabId);
  $$('#side-nav .nav-item').forEach(el =>
        el.classList.toggle('active', !!act && el.dataset.nav === act.type && ['pos','returnsale','sales','inventory','purchase','returnpurch','preport','suppliers','statement','settings','debts'].includes(act.type)));
}

/* ───────────────────────── 10) مدير التبويبات (نمط المتصفح) ───────────────────────── */
let tabs = [], activeTabId = null, posCounter = 1;
const LIVE_TABS = ['sales','inventory','preport','suppliers','statement','debts']; // تبويبات تقريرية تُحدَّث تلقائياً عند فتحها
const TAB_META = {
  pos:       { title: () => `نقطة بيع ${'' + ''}`.trim() || 'نقطة بيع', icon: 'pos' },
  sales:     { title: () => 'تقرير المبيعات',  icon: 'report' },
  inventory: { title: () => 'المخزن',          icon: 'store' },
  purchase:  { title: () => 'قائمة شراء',      icon: 'purchase' },
  preport:   { title: () => 'تقرير المشتريات', icon: 'history' },
  suppliers: { title: () => 'حسابات مجهزين',   icon: 'suppliers' },
    settings:  { title: () => 'الإعدادات',       icon: 'settings' },
  returnsale:  { title: () => 'إرجاع بيع',     icon: 'refresh' },
  returnpurch: { title: () => 'إرجاع شراء',    icon: 'refresh' },
  statement:   { title: () => 'كشف حساب',      icon: 'receipt' },
  debts:       { title: () => 'الديون',          icon: 'dollar' },
  product:   { title: () => 'إضافة صنف',       icon: 'pill' },
  editsale:  { title: () => 'تعديل قائمة بيع', icon: 'edit' },
  editpurch: { title: () => 'تعديل قائمة شراء',icon: 'edit' },
  details:   { title: () => 'تفاصيل صنف',      icon: 'eye' },
  scanner:   { title: () => 'ماسح الفواتير',   icon: 'camera' },
};
function openTab(type, props = {}) {
  // التبويبات الفريدة: واحد من كل نوع (عدا نقطة البيع والتعديلات والتفاصيل)
    const singleton = ['sales','inventory','preport','suppliers','settings','purchase','scanner','returnsale','returnpurch','statement','debts'];
  if (singleton.includes(type)) {
    const ex = tabs.find(t => t.type === type);
    if (ex) { activateTab(ex.id); return ex; }
  }
  let title = props.title || TAB_META[type].title();
  if (type === 'pos' && !props.title) title = `نقطة بيع ${tabs.filter(t => t.type === 'pos').length + 1}`;
  const tab = { id: uid(), type, title, icon: TAB_META[type].icon, props, state: props.state || {} };
  tab.el = h('div', { class: 'tab-pane', dataset: { tab: tab.id } });
  $('#content').append(tab.el);
  tabs.push(tab);
  renderTabStrip();
  activateTab(tab.id);
  renderTabContent(tab);
  return tab;
}
function closeTab(id) {
  const i = tabs.findIndex(t => t.id === id);
  if (i < 0) return;
  tabs[i].el.remove();
  tabs.splice(i, 1);
  if (!tabs.length) { openTab('pos'); return; }
  if (activeTabId === id) activateTab(tabs[Math.max(0, i - 1)].id);
  renderTabStrip();
}
function activateTab(id) {
  activeTabId = id;
  tabs.forEach(t => t.el.classList.toggle('active', t.id === id));
  renderTabStrip();
  markActiveNav();
  const t = tabs.find(x => x.id === id);
  if (t && LIVE_TABS.includes(t.type)) renderTabContent(t);
}
function renderTabStrip() {
  const box = $('#tabs');
  box.innerHTML = '';
  tabs.forEach(t => {
    box.append(h('div', { class: 'tab' + (t.id === activeTabId ? ' active' : ''), onclick: () => activateTab(t.id) },
      h('span', { html: icon(t.icon) }),
      h('span', { class: 'tab-title' }, t.title),
      h('span', { class: 'tab-close', html: icon('close'), onclick: e => { e.stopPropagation(); closeTab(t.id); } })));
  });
  markActiveNav();
}
function renderTabContent(tab) {
  const R = {
    pos: renderPOS, sales: renderSalesReport, inventory: renderInventory,
    purchase: renderPurchase, preport: renderPurchaseReport, suppliers: renderSuppliers,
    settings: renderSettings, product: renderProductForm, editsale: renderEditSale,
        editpurch: renderEditPurchase, details: renderProductDetails, scanner: renderScannerTab,
    returnsale: renderReturnSale, returnpurch: renderReturnPurchase, statement: renderStatement, debts: renderDebts,
  };
  tab.el.innerHTML = '';
  (R[tab.type] || renderPOS)(tab);
}
function refreshActiveTab() {
  const t = tabs.find(x => x.id === activeTabId);
        if (t && !['pos','editsale','editpurch','product','purchase','scanner','returnsale','returnpurch'].includes(t.type)) renderTabContent(t);
  renderSideNav();
}

/* ───────────────────────── 11) مساعدات المنتجات والتعبئة ───────────────────────── */
// units: [{name, perNext}] من الأكبر للأصغر — الأخيرة هي الوحدة الصغرى (perNext=1)
function unitFactor(p, idx) { let f = 1; for (let i = idx; i < p.units.length; i++) f *= (p.units[i].perNext || 1); return f; }
function baseFactor(p) { return unitFactor(p, 0); }
function costPerUnit(p, idx) { return (p.purchasePriceTop / baseFactor(p)) * unitFactor(p, idx); }
function salePerUnit(p, idx) { return p.salePriceBase * unitFactor(p, idx); }
function stockInUnit(p, idx) { return Math.floor((p.stockBase || 0) / unitFactor(p, idx) * 100) / 100; }
function smallUnitName(p) { return p.units[p.units.length - 1].name; }
function bigUnitName(p) { return p.units[0].name; }
/* ═══ محرك البحث العربي الذكي ═══ */
function arNorm(s) {
  return String(s == null ? '' : s).toLowerCase()
    .replace(/[\u064B-\u065F\u0670\u0640]/g, '')            // تشكيل + تطويل
    .replace(/[أإآٱ]/g, 'ا').replace(/[ىيئی]/g, 'ي').replace(/ؤ/g, 'و').replace(/ة/g, 'ه').replace(/ک/g, 'ك')
    .replace(/[\u0660-\u0669]/g, d => d.charCodeAt(0) - 0x0660)
    .replace(/[\u06F0-\u06F9]/g, d => d.charCodeAt(0) - 0x06F0)
    .replace(/[^\p{L}\p{N}\s]/gu, ' ').replace(/\s+/g, ' ').trim();
}
const _stripAl = w => (w.length > 3 && w.startsWith('ال')) ? w.slice(2) : w;   // الاسبرين = اسبرين = أسبرين
const arTokens = s => arNorm(s).split(' ').filter(Boolean).map(_stripAl);
const _prodIdx = new WeakMap();   // WeakMap حتى لا تُخزَّن الفهارس داخل المنتج وتُرسَل إلى Firebase
function _prodIndex(p) {
  const sig = [p.brandName, p.scientificName, p.dose, p.company, p.form].join('\u0001');
  let c = _prodIdx.get(p);
  if (c && c.sig === sig) return c;
  const nameT = arTokens(p.brandName);
  c = { sig, nameT, sciT: arTokens(p.scientificName), otherT: arTokens([p.dose, p.company, p.form].join(' ')), full: nameT.join(' ') };
  _prodIdx.set(p, c);
  return c;
}
function _lev(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i]; let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      cur.push(v); if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}
function _isSubseq(t, w) { let i = 0; for (let j = 0; j < w.length && i < t.length; j++) if (w[j] === t[i]) i++; return i === t.length; }
function _tokScore(t, w, fuzzy) {
  if (w === t) return 100;
  if (w.startsWith(t)) return 80;
  if (t.length >= 2 && w.includes(t)) return 60;          // نسيت الحرف الأول: «سبرين» ← «اسبرين»
  if (!fuzzy || t.length < 3) return 0;
  const max = t.length <= 5 ? 1 : 2;
  let best = _lev(t, w, max);
  if (best > max && w.length > t.length) best = Math.min(best, _lev(t, w.slice(0, t.length), max), _lev(t, w.slice(0, t.length + 1), max));
  if (best <= max) return 45 - best * 10;                  // خطأ إملائي
  if (t.length >= w.length * 0.6 && _isSubseq(t, w)) return 20; // حرف ناقص بالوسط
  return 0;
}
const _W = [['nameT', 1], ['sciT', .85], ['otherT', .6]];
function _scoreProduct(p, qt, fuzzy) {
  const ix = _prodIndex(p); let total = 0;
  for (const t of qt) {
    let best = 0;
    for (const [k, wt] of _W) for (const w of ix[k]) { const s = _tokScore(t, w, fuzzy) * wt; if (s > best) best = s; }
    if (!best) return 0;
    total += best;
  }
  if (ix.full.startsWith(qt.join(' '))) total += 40;
  return total;
}
const _rawQ = q => String(q || '').trim().toLowerCase().replace(/[\u0660-\u0669]/g, d => d.charCodeAt(0) - 0x0660);
function prodMatches(p, q) {   // للفلاتر (المخزن…)
  const qt = arTokens(q); if (!qt.length) return true;
  const raw = _rawQ(q);
  return _scoreProduct(p, qt, true) > 0 || (p.barcodes || []).some(b => String(b).toLowerCase().includes(raw));
}
function searchProducts(q) {
  const raw = _rawQ(q);
  if (!raw) return [];
  const live = state.products.filter(p => !p.deleted);
  const exact = live.find(p => (p.barcodes || []).some(b => String(b).toLowerCase() === raw));
  if (exact) return [exact];
  const qt = arTokens(q);
  const rank = (a, b) => b.s - a.s || a.p.brandName.length - b.p.brandName.length;
  const strict = [];
  for (const p of live) {
    let s = qt.length ? _scoreProduct(p, qt, false) : 0;
    if (!s && (p.barcodes || []).some(b => String(b).toLowerCase().includes(raw))) s = 50;
    if (s) strict.push({ p, s });
  }
  strict.sort(rank);
  let res = strict;
  if (strict.length < 4 && qt.some(t => t.length >= 3)) {      // تنبؤ/تصحيح عند قلة النتائج
    const ids = new Set(strict.map(x => x.p.id)), fz = [];
    for (const p of live) { if (ids.has(p.id)) continue; const s = _scoreProduct(p, qt, true); if (s) fz.push({ p, s }); }
    fz.sort(rank); res = strict.concat(fz);
  }
  return res.slice(0, 12).map(x => x.p);
}

/* ───────────────────────── 12) نقطة البيع ───────────────────────── */
function renderPOS(tab) {
  const st = tab.state;
  st.cart = st.cart || [];           // [{productId,name,unitIdx,qty,cost,sale}]
  st.discount = st.discount || 0;
  st.sideTab = st.sideTab || 'dr';

 const wrap = h('div', { class: 'pos-layout' }); // ★ سلة واحدة بشعار الصيدلية — الزبون يُختار لحظة الحفظ
  const center = h('div', { class: 'pos-center' });

  /* محرك البحث */
  const sInput = h('input', { placeholder: 'ابحث بالاسم أو أدخل الباركود…', autocomplete: 'off' });
  const sugBox = h('div', { class: 'suggestions' });
  st.searchInput = sInput;
    /* ★ وضع تعديل كمية آخر منتج (زر المسطرة) + تدوير التعبئة (Alt×2) */
  const PH = 'ابحث بالاسم أو أدخل الباركود…';
  const lastItem = () => { if (!st.cart.includes(st.lastAdded)) st.lastAdded = st.cart[st.cart.length - 1]; return st.lastAdded; };
  st.qtyMode = false;
  st.enterQtyMode = () => {
    const it = lastItem(); if (!it) return toast('لا يوجد منتج مُضاف للتعديل', 'r');
    st.qtyMode = true;
    const bx = sInput.closest('.search-box'); if (bx) bx.classList.add('qty-mode');
    sInput.setAttribute('inputmode', 'decimal');
    sInput.placeholder = `الكمية الجديدة لـ «${it.name}» — Enter للتأكيد`;
    sInput.value = ''; sugBox.classList.remove('show');
    sInput.focus(); sInput.select();
  };
  st.exitQtyMode = () => {
    st.qtyMode = false;
    const bx = sInput.closest('.search-box'); if (bx) bx.classList.remove('qty-mode');
    sInput.removeAttribute('inputmode'); sInput.placeholder = PH; sInput.value = '';
  };
  st.applyQty = () => {
    const v = num(sInput.value), it = lastItem();
    if (!it || !(v > 0)) return toast('أدخل رقماً أكبر من صفر', 'r');
    it.qty = v; st.exitQtyMode(); st.renderCart(); st.renderTotals();
  };
  st.cyclePack = () => {
    const it = lastItem(); if (!it) return;
    const p = findProd(it.productId);
    if (!p || p.units.length < 2) return toast('هذا المنتج له تعبئة واحدة فقط', 'b');
    let ni = it.unitIdx - 1; if (ni < 0) ni = p.units.length - 1;   // أصغر ← وسطى ← كبرى ← أصغر
    it.unitIdx = ni; it.sale = salePerUnit(p, ni); it.cost = costPerUnit(p, ni);
    const dup = st.cart.find(x => x !== it && x.productId === it.productId && x.unitIdx === ni);
    if (dup) { dup.qty += it.qty; st.cart.splice(st.cart.indexOf(it), 1); st.lastAdded = dup; }
    st.renderCart(); st.renderTotals();
    toast(`${p.brandName} ← ${p.units[ni].name}`, 'b');
  };
  sInput.addEventListener('blur', () => { if (st.qtyMode) st.exitQtyMode(); });
  let selIdx = -1, sugItems = [];
  function renderSugs() {
    const q = sInput.value;
    sugItems = searchProducts(q); selIdx = -1;
    sugBox.innerHTML = '';
    if (!q.trim()) { sugBox.classList.remove('show'); return; }
    if (!sugItems.length) {
      sugBox.append(h('div', { class: 'sug-empty' }, `لا نتائج لـ «${q}» — أضف الصنف من قائمة الشراء`));
    } else {
      sugItems.forEach((p, i) => {
        sugBox.append(h('div', { class: 'sug-item', onclick: () => { pickProduct(p); } },
          h('span', { class: 'sug-ic', html: icon('pill') }),
          h('div', { class: 'sug-name' }, p.brandName, coTag(p),
            h('small', {}, `${p.scientificName || ''}${p.scientificName ? ' • ' : ''}${p.form || ''} ${p.dose || ''}`)),
          h('span', { class: 'sug-stock' + ((p.stockBase || 0) <= (state.settings.lowStock ?? 10) ? ' low' : '') },
            `المخزون: ${fmt(p.stockBase || 0)} ${smallUnitName(p)}`),
          h('span', { class: 'sug-price' }, `${fmt(salePerUnit(p, p.units.length - 1))} ${cur()}`)));
      });
    }
    sugBox.classList.add('show');
  }
  function pickProduct(p) {
    addToCart(tab, p);
    sInput.value = ''; sugBox.classList.remove('show'); sInput.focus();
  }
    sInput.addEventListener('input', () => {
    if (st.qtyMode) { sInput.value = sInput.value.replace(/[\u0660-\u0669]/g, d => d.charCodeAt(0) - 0x0660).replace(/[^\d.]/g, ''); return; }
    renderSugs();
  });
  sInput.addEventListener('keydown', e => {
    if (st.qtyMode) {
      if (e.key === 'Enter') { e.preventDefault(); st.applyQty(); }
      else if (e.key === 'Escape') { e.preventDefault(); st.exitQtyMode(); }
      else if (e.key.length === 1 && !/[0-9.\u0660-\u0669]/.test(e.key) && !e.ctrlKey && !e.metaKey) e.preventDefault();
      return;
    }
    if (e.key === 'Enter') {
      const q = sInput.value.trim();
      if (selIdx >= 0 && sugItems[selIdx]) pickProduct(sugItems[selIdx]);
      else if (sugItems.length === 1 || (q && sugItems.length)) pickProduct(sugItems[0]);
      else if (q) toast('لا يوجد صنف مطابق', 'r');
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!sugItems.length) return;
      selIdx = e.key === 'ArrowDown' ? Math.min(selIdx + 1, sugItems.length - 1) : Math.max(selIdx - 1, 0);
      $$('.sug-item', sugBox).forEach((el, i) => el.classList.toggle('sel', i === selIdx));
    } else if (e.key === 'Escape') { sugBox.classList.remove('show'); }
  });
  document.addEventListener('mousedown', e => { if (!sugBox.contains(e.target) && e.target !== sInput) sugBox.classList.remove('show'); });
  center.append(h('div', { class: 'search-engine' },
    h('div', { class: 'search-box' }, h('span', { html: icon('search') }), sInput,
      h('span', { class: 'search-hint' }, 'أي كتابة تذهب هنا تلقائياً')), sugBox));

  /* جدول السلة */
  const cartWrap = h('div', { class: 'cart-wrap' });
  st.renderCart = () => {
    cartWrap.innerHTML = '';
    if (!st.cart.length) {
      cartWrap.append(h('div', { class: 'cart-empty', inert: true, 'aria-hidden': 'true' },
        h('span', { class: 'cart-watermark', inert: true,
          onmousedown: e => e.preventDefault(), ondragstart: e => e.preventDefault(),
          onselectstart: e => e.preventDefault(), oncontextmenu: e => e.preventDefault(),
          html: `<img src="logo.svg" alt="" draggable="false">` }))); // ★ شعار الصيدلية دائماً
      return;
    }
    const tbody = h('tbody');
    st.cart.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, it.name, coTag(p), h('small', {}, p ? `${p.form || ''} ${p.dose || ''}` : '')),
        h('td', {}, (() => {
          const sel = h('select', { class: 'unit-select' },
            (p ? p.units : [{ name: it.unitName }]).map((u, ui) =>
              h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => {
            it.unitIdx = +sel.value;
            if (p) { it.sale = salePerUnit(p, it.unitIdx); it.cost = costPerUnit(p, it.unitIdx); }
            st.renderCart(); st.renderTotals();
          });
          return sel;
        })()),
        h('td', {}, (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 0.5, step: 'any' });
          q.addEventListener('change', () => { it.qty = Math.max(0.5, num(q.value) || 1); st.renderCart(); st.renderTotals(); });
          return h('div', { class: 'qty-ctl' },
            h('button', { onclick: () => { it.qty++; st.renderCart(); st.renderTotals(); } }, '+'), q,
            h('button', { onclick: () => { if (it.qty > 1) { it.qty--; st.renderCart(); st.renderTotals(); } } }, '−'));
        })()),
        h('td', { class: 'td-num td-cost' }, fmt(it.cost)),
        h('td', { class: 'td-num td-sale' }, fmt(it.sale)),
        h('td', { class: 'td-num td-total' }, fmt(it.sale * it.qty)),
        h('td', {}, (() => {
          const rm = h('button', { class: 'icon-btn del', title: 'إزالة من السلة', html: icon('close'),
            onclick: () => { st.cart.splice(i, 1); st.renderCart(); st.renderTotals(); } });
          return p ? productActions(p, tab, rm) : h('div', { class: 'row-act' }, rm);
        })()),
      ));
    });
    cartWrap.append(h('div', { class: 'tbl-scroll' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {},
          h('th', {}, 'ت'), h('th', {}, 'اسم المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'),
          h('th', {}, 'سعر التكلفة'), h('th', {}, 'سعر البيع'), h('th', {}, 'المجموع'), h('th', {}, 'إجراء'))),
        tbody)));
  };

  /* الإجماليات والأزرار */
  const subEl = h('div', { class: 'tval' }, '0');
  const grandEl = h('div', { class: 'tval' }, h('span', {}, '0'), ' ', h('small', {}, cur()));
  const discInp = h('input', { type: 'number', min: 0, placeholder: '0', value: st.discount || '' });
  const peekTip = h('div', { class: 'peek-tip' });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); st.renderTotals(); });
  discInp.addEventListener('blur', () => { if (tab.id === activeTabId) sInput.focus(); });
  st.renderTotals = () => {
    const sub = st.cart.reduce((s, it) => s + it.sale * it.qty, 0);
    const profit = st.cart.reduce((s, it) => s + (it.sale - it.cost) * it.qty, 0) - st.discount;
    animNum(subEl, sub);
    animNum(grandEl.firstChild, Math.max(0, sub - st.discount));
    peekTip.innerHTML = `<small>الربح الصافي من هذه القائمة</small>${fmt(profit)} ${cur()}`;
  };

  /* ★ مفتاح طباعة الفاتورة — بجانب الخصم وعلامة الربح، يُحفظ فوراً ويُزامَن بين الأجهزة */
  const printSw = h('div', { class: 'pos-print-sw' + (state.settings.printInvoice !== false ? ' on' : ''), title: 'طباعة فاتورة 80مم تلقائياً بعد كل بيع', html: icon('print') });
  printSw.append(h('span', { class: 'sw' }));
  printSw.addEventListener('click', async () => {
    state.settings.printInvoice = !(state.settings.printInvoice !== false);
    printSw.classList.toggle('on', state.settings.printInvoice);
    await save('settings', state.settings);
    toast(state.settings.printInvoice ? 'طباعة الفاتورة: مفعّلة' : 'طباعة الفاتورة: متوقفة', 'b');
  });
  const footer = h('div', { class: 'pos-footer' },
    h('div', { class: 'totals-row' },
      h('div', { class: 'total-card' }, h('label', {}, 'مجموع القائمة'), subEl),
      h('div', { class: 'total-card' }, h('label', {}, 'الخصم'),
        h('div', { class: 'discount-wrap' }, discInp,
          h('div', { class: 'profit-peek', html: icon('dollar') }, peekTip), printSw)),
      h('div', { class: 'total-card grand' }, h('label', {}, 'المبلغ المطلوب'), grandEl)),
    h('div', { class: 'pay-row' },
      h('button', { class: 'pay-btn cash', onclick: () => checkout(tab, 'cash') },
        h('span', { html: icon('cash') }), 'بيع كاش ', h('kbd', {}, 'Ctrl+S')),
      h('button', { class: 'pay-btn electronic', onclick: () => checkout(tab, 'electronic') },
        h('span', { html: icon('card') }), 'بيع إلكتروني'),
      h('button', { class: 'pay-btn credit', onclick: () => checkout(tab, 'credit') },
        h('span', { html: icon('clock') }), 'بيع آجل')));

  center.append(cartWrap);
  const layoutInner = h('div', { style: { flex: 1, display: 'flex', minHeight: 0 } }, center, renderPOSSide(tab));
  wrap.append(layoutInner, footer);
  tab.el.append(wrap);
  st.renderCart(); st.renderTotals();
  setTimeout(() => sInput.focus(), 60);
}

function addToCart(tab, p) {
  const st = tab.state;
  const ex = st.cart.find(it => it.productId === p.id && it.unitIdx === p.units.length - 1);
  if (ex) { ex.qty++; st.lastAdded = ex; }
  else {
    const it = { productId: p.id, name: p.brandName, unitIdx: p.units.length - 1,
      qty: 1, cost: costPerUnit(p, p.units.length - 1), sale: salePerUnit(p, p.units.length - 1) };
    st.cart.push(it); st.lastAdded = it;
  }
  st.renderCart(); st.renderTotals();
}

/* تنفيذ البيع */
/* تنفيذ البيع — الخطوة 1: نافذة سرعة لاختيار الزبون */
async function checkout(tab, pay) {
  const st = tab.state;
  if (st.processing) return;
  if (!st.cart.length) return toast('السلة فارغة', 'r');
  if (pay === 'credit') return openCreditSaleModal(tab);
  openCheckoutCustomer(tab, pay);
}

/* ★ نافذة اختيار الزبون لحظة الحفظ (زر البيع أو Ctrl+S):
   زبون نقدي / دكتورة نادية بضغطة واحدة — أو ابحث عن أي زبون آخر. Enter = زبون نقدي */
function openCheckoutCustomer(tab, pay) {
  const q = h('input', { class: 'cust-search', placeholder: 'ابحث عن زبون آخر… (Enter = زبون نقدي) — أو اضغط رقماً: 1 نقدي، 2 د. نادية', autocomplete: 'off' });
  const list = h('div', { class: 'cust-list' });
  let m;
  const done = cid => { m.close(); finalizeCheckout(tab, pay, cid); };
  const choose = id => {
    if (pay === 'credit' && !id) return toast('البيع الآجل يتطلب زبوناً مسجلاً — اختر دكتورة نادية أو زبوناً آخر', 'r');
    done(id);
  };
  const keyBadge = n => h('span', { class: 'cust-key' }, String(n));
  const bigRow = (id, name, logoHtml, sub, cls, n) => h('button', { class: 'cust-row co-big ' + (cls || ''), onclick: () => choose(id) },
    h('span', { class: 'cust-av', html: logoHtml }),
    h('div', { class: 'cust-nm' }, h('b', {}, name), h('small', {}, sub)),
    keyBadge(n));
  const nadia = findCust(DR_NADIA_ID);
  /* الزبائن المضافون: الأقدم أولاً — رقمهم 3 ثم 4 ثم 5 … */
  const others = () => state.customers.filter(c => !c.deleted && c.id !== DR_NADIA_ID).sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
  list.append(
    bigRow(null, 'زبون نقدي', icon('store'), 'بيع مباشر بدون حساب', '', 1),
    nadia ? bigRow(DR_NADIA_ID, 'دكتورة نادية', '<img src="nadia-logo.svg" alt="">', 'تُحفظ القائمة في حسابها', 'pink', 2) : null);
  const draw = () => {
    list.querySelectorAll('.cust-x').forEach(n => n.remove());
    const s = q.value.trim().toLowerCase();
    if (!s) return;
    others().forEach((c, i) => {
      if (!String(c.name).toLowerCase().includes(s)) return;
      list.append(h('button', { class: 'cust-row cust-x', onclick: () => done(c.id) },
        h('span', { class: 'cust-av' }, esc(String(c.name).trim().charAt(0) || '؟')),
        h('div', { class: 'cust-nm' }, h('b', {}, c.name)),
        i + 3 <= 9 ? keyBadge(i + 3) : null));
    });
  };
  q.addEventListener('input', draw);
  q.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    if (pay === 'credit') { const first = list.querySelector('.cust-x'); if (first) first.click(); else toast('البيع الآجل يتطلب زبوناً مسجلاً', 'r'); }
    else done(null);
  });
  m = openModal({ title: 'حفظ القائمة باسم…', icon: 'users', body: h('div', {}, list, q) });
  /* ★ اختصارات الأرقام: تعمل فقط حين يكون حقل البحث فارغاً (وإلا تُكتب الأرقام في البحث) */
  m.box.addEventListener('keydown', e => {
    if (q.value || e.ctrlKey || e.altKey || e.metaKey) return;
    const mt = /^(?:Digit|Numpad)([1-9])$/.exec(e.code || '');
    if (!mt) return;
    e.preventDefault();
    const n = +mt[1];
    if (n === 1) return choose(null);
    if (n === 2) { if (nadia) choose(DR_NADIA_ID); return; }
    const c = others()[n - 3];
    if (c) choose(c.id); else toast('لا يوجد زبون بهذا الرقم', 'r');
  });
  setTimeout(() => q.focus(), 60);
}

/* ★ بيع آجل: نافذة تطلب اسم الزبون ورقم هاتفه والمبلغ المدفوع — المتبقي يُحسب تلقائياً ويُسجَّل ديناً.
   اختيار اسم موجود يعرض دينه الحالي؛ أي اسم جديد يُحفظ تلقائياً كحساب زبون دائم في تبويب الديون */
function openCreditSaleModal(tab) {
  const st = tab.state;
  const net = Math.max(0, st.cart.reduce((s, it) => s + it.sale * it.qty, 0) - (st.discount || 0));
  const nameInp = h('input', { placeholder: 'اسم الزبون', autocomplete: 'off', list: 'credit-cust-list' });
  const dlist = h('datalist', { id: 'credit-cust-list' },
    state.customers.filter(c => !c.deleted).map(c => h('option', { value: c.name })));
  const phoneInp = h('input', { placeholder: 'رقم الهاتف', type: 'tel', dir: 'ltr', style: { textAlign: 'right' } });
  const paidInp = h('input', { type: 'number', min: 0, step: 'any', placeholder: '0' });
  const debtNote = h('div', { class: 'f-hint', style: { display: 'none', color: 'var(--red)', fontWeight: 900 } });
  const remEl = h('b', {}, fmt(net));
  const matchCust = () => {
    const n = nameInp.value.trim().toLowerCase();
    return n ? state.customers.find(c => !c.deleted && String(c.name).trim().toLowerCase() === n) : null;
  };
  const recalc = () => {
    const c = matchCust();
    if (c) {
      if (c.phone && !phoneInp.value) phoneInp.value = c.phone;
      debtNote.style.display = '';
      debtNote.textContent = `زبون مسجّل — دينه الحالي قبل هذه القائمة: ${fmt(c.debt || 0)} ${cur()}`;
    } else debtNote.style.display = 'none';
    animNum(remEl, Math.max(0, net - num(paidInp.value)));
  };
  nameInp.addEventListener('input', recalc);
  paidInp.addEventListener('input', recalc);
  openModal({
    title: 'بيع آجل — حساب زبون', icon: 'clock',
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card big', style: { textAlign: 'center' } }, h('label', {}, 'إجمالي القائمة المطلوب'), h('b', {}, `${fmt(net)} ${cur()}`))),
      h('div', { class: 'f-field' }, h('label', {}, 'اسم الزبون ', h('span', { class: 'req' }, '*')), nameInp, dlist, debtNote),
      h('div', { class: 'f-field' }, h('label', {}, 'رقم الهاتف'), phoneInp),
      h('div', { class: 'f-field' }, h('label', {}, 'المبلغ المدفوع الآن'), paidInp),
      h('div', { class: 'f-field' }, h('div', { class: 'sum-card r', style: { textAlign: 'center' } }, h('label', {}, 'المتبقي (يُسجَّل ديناً)'), remEl))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'حفظ البيع الآجل', cls: 'g', icon: 'check', big: true, onClick: async c => {
        const name = nameInp.value.trim();
        if (!name) return toast('أدخل اسم الزبون أولاً', 'r');
        const paid = num(paidInp.value);
        if (paid < 0 || paid > net) return toast('المبلغ المدفوع يجب أن يكون بين 0 وإجمالي القائمة', 'r');
        let cust = matchCust();
        if (cust) {
          const ph = phoneInp.value.trim();
          if (ph && ph !== cust.phone) { cust.phone = ph; await save('customers', cust); }
        } else {
          cust = { id: uid(), name, phone: phoneInp.value.trim(), debt: 0, createdAt: Date.now() };
          await save('customers', cust);
          toast(`حُفظ «${name}» كحساب زبون جديد`, 'b');
        }
        c();
        finalizeCheckout(tab, 'credit', cust.id, paid);
      } },
    ],
  });
  setTimeout(() => nameInp.focus(), 60);
}

/* تنفيذ البيع — الخطوة 2: الحفظ الفعلي في حساب الزبون المختار */
async function finalizeCheckout(tab, pay, customerId, paidAmount) {
  const st = tab.state;
  if (st.processing || !st.cart.length) return;
  st.processing = true; // قفل مؤقت لمنع الضغط المزدوج
  const acc = me();
  const items = st.cart.map(it => {
    const p = findProd(it.productId);
    return { ...it, unitName: p ? p.units[it.unitIdx].name : it.unitName || '', qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.sale * it.qty };
  });
  const subtotal = items.reduce((s, it) => s + it.total, 0);
  const cost = items.reduce((s, it) => s + it.cost * it.qty, 0);
  const net = Math.max(0, subtotal - st.discount);
  const ts = Date.now();
  const sale = {
    id: uid(), type: 'sale', version: 1, versions: [],
    items, subtotal, discount: st.discount, net, cost, profit: net - cost,
    pay, customerId: customerId || null, customerName: customerId ? (findCust(customerId) || {}).name : 'زبون نقدي',
    employeeId: acc.id, employeeName: acc.name,
    ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
  };
  if (pay === 'credit') { // الآجل: المدفوع الآن + المتبقي ديناً على حساب الزبون
    sale.paid = Math.min(Math.max(0, num(paidAmount)), net);
    sale.remaining = net - sale.paid;
  } else { sale.paid = net; sale.remaining = 0; }
  await save('sales', sale);
  if (pay === 'credit' && sale.remaining > 0 && customerId) {
    const cust = findCust(customerId);
    if (cust) { cust.debt = (cust.debt || 0) + sale.remaining; await save('customers', cust); }
  }
  for (const it of items) {  // خصم المخزون فوراً
    const p = findProd(it.productId);
    if (p) { p.stockBase = (p.stockBase || 0) - it.qtyBase; await save('products', p); }
  }
  st.cart = []; st.discount = 0; st.processing = false;
  renderTabContent(tab);
  renderSideNav();
  toast(`تمت عملية البيع بنجاح — ${fmt(net)} ${cur()}${customerId ? ` — ${sale.customerName}` : ''}${pay === 'credit' && sale.remaining > 0 ? ` (المتبقي دين: ${fmt(sale.remaining)} ${cur()})` : ''}`);
  if (state.settings.printInvoice !== false) printSaleInvoice(sale);
}

/* اللوح الجانبي لنقطة البيع */
/* ═══ زبون دكتورة نادية: زبون ثابت له تبويب مبيعات ذكي في نقطة البيع ═══ */
const DR_NADIA_ID = 'cust_dr_nadia';

function renderPOSSide(tab) {
  const st = tab.state;
  const side = h('div', { class: 'pos-side' });
  const body = h('div', { class: 'side-body' });
  const tabsBar = h('div', { class: 'side-tabs' });

  /* ★ تبويب دكتورة نادية دائم الظهور للإضافة السريعة — الزبون نفسه يُختار لحظة الحفظ */
  const TABS = [['dr', 'دكتورة نادية'], ['featured', 'المميز'], ['invoices', 'الفواتير السابقة'], ['shortage', 'النواقص'], ['shift', 'تقرير الشفت']];
  if (!TABS.some(([k]) => k === st.sideTab)) st.sideTab = 'dr';

  function draw() {
    tabsBar.innerHTML = '';
    TABS.forEach(([k, l]) => tabsBar.append(
      h('div', { class: 'side-tab' + (st.sideTab === k ? ' active' : ''), onclick: () => { st.sideTab = k; draw(); } }, l)));
    body.innerHTML = '';
    if (st.sideTab === 'dr') drawDrNadia(tab, body);
    else if (st.sideTab === 'featured') drawFeatured(tab, body);
    else if (st.sideTab === 'invoices') drawInvoices(body);
    else if (st.sideTab === 'shortage') drawShortage(body);
    else drawShift(body);
  }
  side.append(tabsBar, body);
  draw();
  return side;
}

/* ★ تبويب دكتورة نادية — جدول مدمج: كل صنف صف صغير (الاسم + مرات البيع)،
   القائمة كاملة بلا اقتطاع ولا «+3»، مرتبة تنازلياً: الأكثر بيعاً في الأعلى */
function drawDrNadia(tab, body) {
  const hidden = new Set(state.settings.drHidden || []);
  const tally = new Map();
  state.sales.filter(s => s.type === 'sale' && s.customerId === DR_NADIA_ID)
    .forEach(s => (s.items || []).forEach(it => {
      if (!it.productId) return;
      const e = tally.get(it.productId) || { qty: 0, count: 0 };
      e.qty += (it.qtyBase != null ? it.qtyBase : it.qty) || 0;
      e.count += 1;
      tally.set(it.productId, e);
    }));
  const rows = [...tally.entries()]
    .filter(([pid]) => !hidden.has(pid) && findProd(pid))
    .map(([pid, e]) => ({ p: findProd(pid), count: e.count, qty: e.qty }))
    .sort((a, b) => (b.count - a.count) || (b.qty - a.qty));   /* تنازلي صارم */

  body.append(h('div', { class: 'side-actions' },
    h('button', { class: 'mini-btn red', onclick: () => openDrHiddenModal(tab) }, h('span', { html: icon('trash') }), 'الأصناف المخفية')));

  if (!rows.length) {
    body.append(h('div', { class: 'empty-note' }, 'لا مبيعات مسجّلة للدكتورة نادية بعد',
      h('br'), 'عند حفظ أي قائمة بيع اختر «دكتورة نادية» ليظهر ترتيب أصنافها هنا'));
    return;
  }
  const tbody = h('tbody');
  rows.forEach((r, i) => tbody.append(h('tr', { class: 'dr-row', title: 'اضغط للإضافة للسلة', onclick: () => addToCart(tab, r.p) },
    h('td', { class: 'td-seq' }, i + 1),
    h('td', { class: 'td-name' }, r.p.brandName, coTag(r.p)),
    h('td', {}, h('span', { class: 'badge b' }, `${r.count}×`)),
    h('td', { class: 'td-num', style: { fontSize: '12px' } }, fmt(salePerUnit(r.p, r.p.units.length - 1))),
    h('td', {}, h('button', { class: 'dr-del2', title: 'إخفاء هذا الصنف من التبويب نهائياً', html: icon('close'),
      onclick: async e => {
        e.stopPropagation();
        const yes = await confirmBox(`إخفاء «${r.p.brandName}» من تبويب دكتورة نادية؟ لن يظهر هنا بعد الآن.`, { danger: true, okLabel: 'إخفاء' });
        if (!yes) return;
        state.settings.drHidden = [...(state.settings.drHidden || []), r.p.id];
        await save('settings', state.settings);
        renderTabContent(tab);
        toast(`أُخفي «${r.p.brandName}» من تبويب دكتورة نادية`, 'b');
      } })))));
  body.append(h('div', { class: 'tbl-scroll dr-table' },
    h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'الصنف'), h('th', {}, 'مرات البيع'), h('th', {}, 'السعر'), h('th', {}, ''))),
      tbody)));
}

function openDrHiddenModal(tab) {
  const list = h('div', { style: { maxHeight: '320px', overflowY: 'auto' } });
  const hidden = state.settings.drHidden || [];
  if (!hidden.length) list.append(h('div', { class: 'empty-note' }, 'لا أصناف مخفية'));
  hidden.forEach(pid => {
    const p = findProd(pid);
    list.append(h('div', { class: 'inv-mini', onclick: async () => {
      state.settings.drHidden = (state.settings.drHidden || []).filter(x => x !== pid);
      await save('settings', state.settings);
      m.close();
      renderTabContent(tab);
      toast('أُعيد الصنف إلى التبويب');
    } },
      h('div', { class: 'im-top' }, h('span', {}, p ? p.brandName : '(صنف محذوف)'), h('span', { class: 'badge g' }, 'اضغط لإعادة الإظهار'))));
  });
  const m = openModal({ title: 'الأصناف المخفية من تبويب دكتورة نادية', icon: 'trash', body: list });
}

function drawFeatured(tab, body) {
  body.append(h('div', { class: 'side-actions' },
    h('button', { class: 'mini-btn green', onclick: () => pickFeaturedModal() }, h('span', { html: icon('plus') }), 'إضافة'),
    h('button', { class: 'mini-btn red', onclick: () => removeFeaturedModal() }, h('span', { html: icon('trash') }), 'حذف')));
  const feats = state.products.filter(p => !p.deleted && p.featured);
  if (!feats.length) { body.append(h('div', { class: 'empty-note' }, 'لا أصناف مميزة بعد', h('br'), 'أضفها بزر الإضافة أعلاه')); return; }
  const grid = h('div', { class: 'feat-grid' });
  feats.forEach(p => grid.append(h('div', { class: 'feat-cell', onclick: () => { addToCart(tab, p); } },
    h('span', { html: icon('pill') }), p.brandName,
    h('span', { class: 'feat-price' }, `${fmt(salePerUnit(p, p.units.length - 1))} ${cur()}`))));
  body.append(grid);
}
function pickFeaturedModal() {
  const inp = h('input', { placeholder: 'ابحث عن الصنف…', style: { width: '100%', border: '1.5px solid var(--line)', borderRadius: '12px', padding: '11px 14px', fontWeight: 800, outline: 'none' } });
  const list = h('div', { style: { marginTop: '12px', maxHeight: '300px', overflowY: 'auto' } });
  const draw = () => {
    list.innerHTML = '';
    const res = searchProducts(inp.value).filter(p => !p.featured);
    if (!res.length) { list.append(h('div', { class: 'empty-note' }, inp.value ? 'لا نتائج' : 'اكتب للبحث')); return; }
    res.forEach(p => list.append(h('div', { class: 'inv-mini', onclick: async () => { p.featured = true; await save('products', p); m.close(); refreshActiveTab(); toast(`«${p.brandName}» أصبح مميزاً`); } },
      h('div', { class: 'im-top' }, h('span', {}, p.brandName), h('b', {}, `${fmt(salePerUnit(p, p.units.length - 1))}`)))));
  };
  inp.addEventListener('input', draw); draw();
  const m = openModal({ title: 'إضافة صنف للمميز', icon: 'star', body: h('div', {}, inp, list) });
  inp.focus();
}
function removeFeaturedModal() {
  const feats = state.products.filter(p => !p.deleted && p.featured);
  const list = h('div', { style: { maxHeight: '320px', overflowY: 'auto' } });
  if (!feats.length) list.append(h('div', { class: 'empty-note' }, 'لا أصناف مميزة'));
  feats.forEach(p => list.append(h('div', { class: 'inv-mini', onclick: async () => { p.featured = false; await save('products', p); m.close(); refreshActiveTab(); toast(`أُزيل «${p.brandName}» من المميز`, 'b'); } },
    h('div', { class: 'im-top' }, h('span', {}, p.brandName), h('span', { class: 'badge r' }, 'إزالة من المميز')))));
  const m = openModal({ title: 'حذف من المميز', icon: 'trash', body: list });
}
function drawInvoices(body) {
  const today = dateStr();
  const recent = state.sales.filter(s => s.type === 'sale').sort((a, b) => b.ts - a.ts).slice(0, 30);
  if (!recent.length) { body.append(h('div', { class: 'empty-note' }, 'لا فواتير بعد')); return; }
  recent.forEach(s => body.append(h('div', { class: 'inv-mini', onclick: () => viewSaleModal(s) },
    h('div', { class: 'im-top' }, h('span', {}, `${s.employeeName} • ${s.customerName || 'زبون نقدي'}`), h('b', {}, `${fmt(s.net)} ${cur()}`)),
    h('div', { class: 'im-sub' }, h('span', {}, `${fmtDate(s.ts)} ${fmtTime(s.ts)}`),
      h('span', { class: 'badge ' + (s.pay === 'cash' ? 'g' : s.pay === 'electronic' ? 'b' : 'r') },
        s.pay === 'cash' ? 'كاش' : s.pay === 'electronic' ? 'إلكتروني' : 'آجل')))));
}
function viewSaleModal(s) {
  const rows = s.items.map((it, i) => h('tr', {},
    h('td', { class: 'td-seq' }, i + 1), h('td', { class: 'td-name' }, it.name),
    h('td', {}, it.unitName), h('td', { class: 'td-num' }, fmt(it.qty)),
    h('td', { class: 'td-num' }, fmt(it.sale)), h('td', { class: 'td-num td-total' }, fmt(it.total))));
  const isCredit = s.pay === 'credit';
  const paid = s.paid != null ? s.paid : (isCredit ? 0 : s.net);
  const remaining = s.remaining != null ? s.remaining : (isCredit ? s.net : 0);
  openModal({
    title: `فاتورة — ${fmtDate(s.ts)} ${fmtTime(s.ts)}`, icon: 'receipt', wide: true,
    body: h('div', {},
      h('table', { class: 'tbl' }, h('thead', {}, h('tr', {},
        h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'السعر'), h('th', {}, 'المجموع'))),
        h('tbody', {}, rows)),
      h('div', { style: { display: 'flex', gap: '10px', marginTop: '14px' } },
        h('div', { class: 'sum-card n' }, h('label', {}, 'المجموع'), h('b', {}, animSpan(s.subtotal))),
        h('div', { class: 'sum-card r' }, h('label', {}, 'الخصم'), h('b', {}, animSpan(s.discount))),
        h('div', { class: 'sum-card big' }, h('label', {}, 'الصافي'), h('b', {}, animSpan(s.net, ' ' + cur()))),
        isCredit ? h('div', { class: 'sum-card g' }, h('label', {}, 'المدفوع'), h('b', {}, animSpan(paid, ' ' + cur()))) : null,
        isCredit ? h('div', { class: 'sum-card r' }, h('label', {}, 'المتبقي (دين)'), h('b', {}, animSpan(remaining, ' ' + cur()))) : null)),
    actions: [
      { label: 'إغلاق', cls: 'n', onClick: c => c() },
      { label: 'طباعة الفاتورة', cls: 'g', icon: 'print', big: true, onClick: () => printSaleInvoice(s) },
    ],
  });
}
function drawShortage(body) {
  const low = state.products.filter(p => !p.deleted && (p.stockBase || 0) <= (state.settings.lowStock ?? 10))
    .sort((a, b) => (a.stockBase || 0) - (b.stockBase || 0));
  if (!low.length) { body.append(h('div', { class: 'empty-note' }, 'ممتاز! لا نواقص حالياً')); return; }
  low.forEach(p => body.append(h('div', { class: 'inv-mini', onclick: () => openTab('details', { productId: p.id }) },
    h('div', { class: 'im-top' }, h('span', {}, p.brandName),
      h('span', { class: 'badge ' + ((p.stockBase || 0) <= 0 ? 'r' : 'amber') }, `${fmt(p.stockBase || 0)} ${smallUnitName(p)}`)),
    h('div', { class: 'im-sub' }, h('span', {}, p.scientificName || p.form || ''), h('span', {}, (p.stockBase || 0) <= 0 ? 'نافد' : 'شبه نافد')))));
}
function drawShift(body) {
  const acc = me();
  const today = dateStr();
  const mine = state.sales.filter(s => s.employeeId === acc.id && s.date === today);
  const sales = mine.filter(s => s.type === 'sale'), returns = mine.filter(s => s.type === 'return');
  const cash = sales.filter(s => s.pay === 'cash').reduce((x, s) => x + s.net, 0);
  const elec = sales.filter(s => s.pay === 'electronic').reduce((x, s) => x + s.net, 0);
  const cred = sales.filter(s => s.pay === 'credit').reduce((x, s) => x + s.net, 0);
  const ret = returns.reduce((x, s) => x + s.net, 0);
  const profit = mine.reduce((x, s) => x + s.profit, 0);
  body.append(h('div', { class: 'shift-cards' },
    h('div', { class: 'shift-card n' }, h('label', {}, `عدد قوائم اليوم (${acc.name})`), h('b', {}, animSpan(sales.length))),
    h('div', { class: 'shift-card g' }, h('label', {}, 'مبيعات كاش'), h('b', {}, animSpan(cash, ' ' + cur()))),
    h('div', { class: 'shift-card b' }, h('label', {}, 'مبيعات إلكترونية'), h('b', {}, animSpan(elec, ' ' + cur()))),
    h('div', { class: 'shift-card r' }, h('label', {}, 'مبيعات آجلة'), h('b', {}, animSpan(cred, ' ' + cur()))),
    h('div', { class: 'shift-card r' }, h('label', {}, 'المرتجعات'), h('b', {}, animSpan(ret, ' ' + cur()))),
    h('div', { class: 'shift-card g' }, h('label', {}, 'صافي الدخل (كاش + إلكتروني)'), h('b', {}, animSpan(cash + elec - ret, ' ' + cur()))),
    h('div', { class: 'shift-card b' }, h('label', {}, 'ربح الشفت'), h('b', {}, animSpan(profit, ' ' + cur()))),
  ));
}

/* ───────────────────────── 13) لوحة المفاتيح الذكية ─────────────────────────
   أي إدخال نصي/رقمي يذهب تلقائياً لمحرك البحث ما لم يكن المستخدم
   داخل حقل إدخال محدد — يعمل مع قارئ الباركود تلقائياً. */

   // ① السطران الجديدان: فوق سطر document.addEventListener مباشرة (خارج الدالة)
const QTY_KEYS = new Set(['Space']);
let _lastAlt = 0;

document.addEventListener('keydown', e => {
  if (!e.repeat && !e.ctrlKey && !e.metaKey && !$('#modal-root').children.length) {
    const pt = tabs.find(x => x.id === activeTabId);
    if (pt && pt.type === 'pos' && pt.state.searchInput && !pt.state.qtyMode) {
      const ae = document.activeElement, si = pt.state.searchInput;
      const isField = ae && (/^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName) || ae.isContentEditable);
      if (!si.value && (ae === si || !isField)) {
        if (QTY_KEYS.has(e.code)) { e.preventDefault(); pt.state.enterQtyMode(); return; }
        if (e.key === 'Alt') {
          e.preventDefault();
          const now = performance.now();
          if (now - _lastAlt < 450) { _lastAlt = 0; pt.state.cyclePack(); } else _lastAlt = now;
          return;
        }
      }
    }
  }
  if (e.ctrlKey && (e.key === 's' || e.key === 'S')) {
    e.preventDefault();
    const t = tabs.find(x => x.id === activeTabId);
    if (t && t.type === 'pos') checkout(t, 'cash');
    return;
  }
  if (e.ctrlKey || e.altKey || e.metaKey) return;
  if ($('#modal-root').children.length) return; // مودال مفتوح
  if (e.key === '+') return; // زر الزائد مخصص للحاسبة — لا يُسرَّب إلى بحث نقطة البيع
  const t = tabs.find(x => x.id === activeTabId);
    if (!t || !['pos','returnsale'].includes(t.type) || !t.state.searchInput) return;
  const ae = document.activeElement;
  if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT' || ae.isContentEditable)) return;
  if (e.key.length === 1) {
    t.state.searchInput.focus();
    t.state.searchInput.value += e.key;
    t.state.searchInput.dispatchEvent(new Event('input'));
    e.preventDefault();
  } else if (e.key === 'Enter' && t.state.searchInput.value.trim()) {
    t.state.searchInput.focus();
    t.state.searchInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    e.preventDefault();
  }
});

/* ───────────────────────── 14) صفحة إضافة / تعديل صنف ───────────────────────── */
function genBarcode() {
  state.settings.generatedBarcode = (state.settings.generatedBarcode || 0) + 1;
  const code = String(state.settings.generatedBarcode).padStart(6, '0');
  DB.put('settings', state.settings);
  return code;
}
/* ═══ محرّك الباركود Code128B (أوفلاين، بلا مكتبات خارجية) + طباعة ملصق 38×25 مم ═══ */
const C128 = ['212222','222122','222221','121223','121322','131222','122213','122312','132212','221213','221312','231212','112232','122132','122231','113222','123122','123221','223211','221132','221231','213212','223112','312131','311222','321122','321221','312212','322112','322211','212123','212321','232121','111323','131123','131321','112313','132113','132311','211313','231113','231311','112133','112331','132131','113123','113321','133121','313121','211331','231131','213113','213311','213131','311123','311321','331121','312113','312311','332111','314111','221411','431111','111224','111422','121124','121421','141122','141221','112214','112412','122114','122411','142112','142211','241211','221114','413111','241112','134111','111242','121142','121241','114212','124112','124211','411212','421112','421211','212141','214121','412121','111143','111341','131141','114113','114311','411113','411311','113141','114131','311141','411131','211412','211214','211232','2331112'];

function code128Bits(text) {
  const s = String(text == null ? '0' : text);
  const vals = [104];                                   // START B
  for (const ch of s) { let c = ch.charCodeAt(0); if (c < 32 || c > 126) c = 63; vals.push(c - 32); }
  let sum = 104; for (let i = 1; i < vals.length; i++) sum += vals[i] * i;
  vals.push(sum % 103); vals.push(106);                 // CHECK + STOP
  return vals.map(v => C128[v].split('').map((w, i) => (i % 2 ? '0' : '1').repeat(+w)).join('')).join('');
}
/* يُعيد عنصر SVG لا يعتمد على أي صورة خارجية (يعمل أوفلاين ومطابق لـ CSP) */
function barcodeSVG(text, { height = 34, module = 2, quiet = 10 } = {}) {
  const bits = code128Bits(text);
  const w = bits.length * module + quiet * 2;
  let rects = '', i = 0;
  while (i < bits.length) {
    if (bits[i] === '1') {
      let j = i; while (j < bits.length && bits[j] === '1') j++;
      rects += `<rect x="${quiet + i * module}" y="0" width="${(j - i) * module}" height="${height}" fill="#000"/>`;
      i = j;
    } else i++;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${height}" preserveAspectRatio="none" style="width:100%;height:${height}px;display:block">${rects}</svg>`;
}

/* النص الافتراضي للملصق: اسم البراند + الشركة + الجرعة + الشكل (كل ما تريد طباعته تلقائياً) */
function barcodeDefaultLabel(p) {
  return [p && p.brandName, p && p.company, p && p.dose, p && p.form].filter(Boolean).join(' • ');
}

/* شاشة الطباعة — نقرة واحدة على أي باركود تفتحها */
function openBarcodePrint(p, code) {
  const defLabel = barcodeDefaultLabel(p) || String(code);
  const lblInp = h('input', { value: defLabel, placeholder: 'النص الظاهر على الملصق' });
  const qtyInp = h('input', { type: 'number', min: 1, value: 1, style: { width: '110px' } });
  const preview = h('div', { class: 'print-label' });
  const paint = () => {
    preview.innerHTML = '';
    preview.append(
      h('div', { class: 'pl-name' }, lblInp.value.trim() || defLabel),
      h('div', { class: 'pl-code', html: barcodeSVG(code) }),
      h('div', { class: 'pl-num' }, String(code)));
  };
  lblInp.addEventListener('input', paint); paint();
  openModal({
    title: `طباعة باركود — ${(p && p.brandName) || code}`, icon: 'barcode', wide: true,
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('label', {}, 'معاينة الملصق (بالأبعاد الحقيقية 38×25 مم)'),
        h('div', { style: { display: 'flex', justifyContent: 'center', padding: '18px', background: '#eef2f7', borderRadius: '14px' } }, preview)),
      h('div', { class: 'f-field full' }, h('label', {}, 'اسم الملصق (قابل للتعديل بالكامل)'), lblInp),
      h('div', { class: 'f-field' }, h('label', {}, 'عدد الملصقات المطبوعة'), qtyInp),
      h('div', { class: 'f-field' }, h('label', {}, 'رقم الباركود'), h('div', { style: { direction: 'ltr', fontWeight: 900, fontSize: '16px' } }, String(code))),
            h('div', { class: 'f-field full' }, h('div', { class: 'f-hint' },
        `طباعة صامتة مباشرة على «${(state.settings.printer || {}).name || 'الطابعة الافتراضية'}» بمقاس ${(state.settings.printer || {}).w || 38}×${(state.settings.printer || {}).h || 25} مم — الطابعة والأبعاد من: الإعدادات ← الطابعة والملصقات`))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'طباعة', cls: 'g', icon: 'print', big: true,
        onClick: () => { printBarcodeLabels(lblInp.value.trim() || defLabel, code, Math.max(1, Math.round(num(qtyInp.value)) || 1)); } },
    ],
  });
  setTimeout(() => { lblInp.focus(); lblInp.select(); }, 80);
}

/* ★ يضبط مقاس صفحة الطباعة ديناميكياً حسب إعدادات الطابعة (يتغلب على قاعدة 38×25 الثابتة) */
function setLabelPage(wMm, hMm) {
  let st = document.getElementById('label-page-style');
  if (!st) { st = h('style', { id: 'label-page-style' }); document.head.append(st); }
  st.textContent = `@page{size:${wMm}mm ${hMm}mm;margin:0}
@media print{.print-area .print-label{width:${wMm}mm!important;height:${hMm}mm!important;border:0;page-break-after:always}
.print-area .print-label:last-child{page-break-after:auto}}`;
}

/* ★ طباعة صامتة مباشرة عبر Electron: الطابعة والأبعاد من الإعدادات — بلا نافذة إعدادات وبلا هدر ملصقات.
   في المتصفح (أو عند فشل الطباعة الصامتة) يسقط تلقائياً على نافذة النظام. */
async function printBarcodeLabels(name, code, qty) {
  const pr = state.settings.printer || {};
  const wMm = pr.w || 38, hMm = pr.h || 25;
  qty = Math.max(1, Math.min(500, Math.round(+qty) || 1));
  if (window.desktop && window.desktop.print) {
    try {
      const r = await window.desktop.print.silent({
        deviceName: pr.name || '', widthMm: wMm, heightMm: hMm, qty,
        name: String(name || ''), code: String(code), svg: barcodeSVG(code) });
      if (r && r.ok) toast(`طُبعت ${qty} ملصقاً على «${pr.name || 'الطابعة الافتراضية'}»`);
      else if (!(r && /cancel/i.test(r.reason || '')))
        toast(`فشلت الطباعة (${(r && r.reason) || 'غير معروف'}) — راجع الإعدادات ← الطابعة`, 'r');
    } catch (e) { toast('تعذّر الوصول إلى الطابعة', 'r'); }
    return;
  }
  /* المتصفح فقط */
  const old = document.getElementById('print-root'); if (old) old.remove();
  setLabelPage(wMm, hMm);
  const root = h('div', { id: 'print-root', class: 'print-area' });
  const svg = barcodeSVG(code);
  for (let i = 0; i < qty; i++) {
    const lb = h('div', { class: 'print-label' },
      h('div', { class: 'pl-name' }, name), h('div', { class: 'pl-code', html: svg }), h('div', { class: 'pl-num' }, String(code)));
    lb.style.width = wMm + 'mm'; lb.style.height = hMm + 'mm';
    root.append(lb);
  }
  document.body.append(root);
  window.print();
  setTimeout(() => root.remove(), 600);
}

const FORMS = ['Tab','Cap','Amp','Vial','Gum','Syrup','Susp','Supp'];
const DOSE_UNITS = ['mg','g','ml','mcg','IU','%'];
function renderProductForm(tab) {
  const P = tab.props;
  const existing = P.productId ? findProd(P.productId) : null;
    const f = tab.state.form = existing ? JSON.parse(JSON.stringify(existing)) : {
    brandName: '', scientificName: '', barcodes: P.barcode ? [P.barcode] : [],
    form: 'Tab', dose: '', expiry: '', featured: false, company: '', country: '',
        units: [{ name: 'قطعة', perNext: 1 }],
    purchasePriceTop: 0, salePriceBase: 0, stockBase: 0, supplierId: P.supplierId || null,
  };
    if (!f.units || !f.units.length) f.units = [{ name: 'قطعة', perNext: 1 }];
  f.units[f.units.length - 1].perNext = 1;

  const page = h('div', { class: 'page', style: { overflowY: 'auto' } });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('pill') }), existing ? `تعديل صنف: ${existing.brandName}` : 'إضافة صنف جديد'),
    h('div', { class: 'spacer' }),
    h('button', { class: 'btn b', onclick: () => openTab('scanner', { returnTab: tab.id }) }, h('span', { html: icon('camera') }), 'مسح فاتورة بالذكاء الاصطناعي')));

  const grid = h('div', { class: 'form-grid' });
  const nameInp = h('input', { value: f.brandName, placeholder: 'اسم العلاج التجاري' });
  const sciInp = h('input', { value: f.scientificName || '', placeholder: 'اختياري' });
    /* الشركة المصنعة + البلد — قائمة ذكية: اختر منها، أو اكتب حرفاً للترشيح، أو اكتب اسماً جديداً فيُحفظ */
  if (!Array.isArray(state.settings.companies) || !state.settings.companies.length) state.settings.companies = DEFAULT_COMPANIES.map(c => ({ ...c }));
  const companies = state.settings.companies;
  const compInp = h('input', { value: f.company || '', placeholder: 'اختر من القائمة أو اكتب اسم شركة…', autocomplete: 'off' });
  const compSug = h('div', { class: 'suggestions' });
  const ctryListId = 'ctry-' + tab.id;
  const countryInp = h('input', { value: f.country || '', placeholder: 'تُملأ تلقائياً — ويمكن تعديلها أو كتابتها', list: ctryListId });
  const countryList = h('datalist', { id: ctryListId });
  function drawCountryList() {
    countryList.innerHTML = '';
    [...new Set(companies.map(c => c.country).filter(Boolean))].forEach(ct => countryList.append(h('option', { value: ct })));
  }
    function drawCompSug() {
    const q = compInp.value.trim().toLowerCase();
    compSug.innerHTML = '';
    const all = companies.filter(c => c && c.name);
    /* عند الكتابة: كل المطابقات. عند الفراغ: حتى 60 شركة (كان 30 فتُقطع الشركات الجديدة) */
    let res = q ? all.filter(c => c.name.toLowerCase().includes(q)) : all.slice(0, 60);
    /* الأدقّ أولاً: ما يبدأ بالحرف المكتوب ثم ما يحتويه */
    if (q) res = res.sort((a, b) => (a.name.toLowerCase().startsWith(q) ? 0 : 1) - (b.name.toLowerCase().startsWith(q) ? 0 : 1));
    res.forEach(c => compSug.append(h('div', { class: 'sug-item', onclick: () => {
      compInp.value = c.name; f.company = c.name;
      if (c.country) { countryInp.value = c.country; f.country = c.country; }
      compSug.classList.remove('show');
    } },
      h('span', { class: 'sug-ic', html: icon('store') }),
      h('div', { class: 'sug-name' }, c.name, h('small', {}, c.country || '')))));
    if (q && !res.length) compSug.append(h('div', { class: 'sug-empty' }, `«${compInp.value.trim()}» غير مسجّلة — ستُحفظ كشركة جديدة عند حفظ الصنف`));
    if (res.length || q) compSug.classList.add('show');
  }

  compInp.addEventListener('input', () => { f.company = compInp.value.trim(); drawCompSug(); });
  compInp.addEventListener('focus', drawCompSug);
  compInp.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    const q = compInp.value.trim().toLowerCase();
    const hit = companies.find(c => c.name.trim().toLowerCase() === q) || companies.find(c => c.name.toLowerCase().includes(q));
    if (!hit) return;
    compInp.value = hit.name; f.company = hit.name;
    if (hit.country) { countryInp.value = hit.country; f.country = hit.country; }
    compSug.classList.remove('show');
  });

  compInp.addEventListener('blur', () => setTimeout(() => compSug.classList.remove('show'), 160));
  countryInp.addEventListener('input', () => f.country = countryInp.value.trim());
  drawCountryList();
  const formSel = h('select', {}, FORMS.map(x => h('option', { value: x, selected: f.form === x }, x)), h('option', { value: '__add' }, '＋ إضافة شكل جديد…'));
  formSel.addEventListener('change', async () => {
    if (formSel.value === '__add') {
      const v = await promptBox('إضافة شكل علاجي جديد', { placeholder: 'مثال: Drops' });
      if (v) { FORMS.push(v); formSel.insertBefore(h('option', { value: v }, v), formSel.lastChild); formSel.value = v; }
      else formSel.value = f.form;
    } else f.form = formSel.value;
  });
  const doseInp = h('input', { value: f.dose || '', placeholder: 'مثال: 500', style: { flex: 1 } });
  const doseUnit = h('select', {}, DOSE_UNITS.map(u => h('option', {}, u)));
  const expiryInp = h('input', { type: 'month', value: f.expiry || '' });
  const stockInp = h('input', { type: 'number', min: 0, step: 'any', placeholder: '0' });
  const stockUnit = h('select', {});


  /* الباركودات */
  const bcInp = h('input', { placeholder: 'أدخل باركود ثم Enter', style: { direction: 'ltr' } });
  const bcList = h('div', { class: 'barcode-list' });
    const drawBarcodes = () => {
    bcList.innerHTML = '';
    f.barcodes.forEach((b, i) => bcList.append(
      h('span', { class: 'barcode-chip clickable', title: 'اضغط لطباعة ملصق هذا الباركود',
          onclick: () => openBarcodePrint({ ...f, brandName: (nameInp.value || f.brandName || '').trim() }, b) },
        b,
        h('button', { class: 'bc-print', title: 'طباعة الملصق', html: icon('print'),
          onclick: e => { e.stopPropagation(); openBarcodePrint({ ...f, brandName: (nameInp.value || f.brandName || '').trim() }, b); } }),
        h('button', { class: 'bc-del', title: 'حذف الباركود', html: icon('close'),
          onclick: e => { e.stopPropagation(); f.barcodes.splice(i, 1); drawBarcodes(); } }))));
  };
  const addBarcode = v => {
    v = v.trim();
    if (!v) return;
    if (state.products.some(p => !p.deleted && p.id !== f.id && (p.barcodes || []).includes(v))) return toast('هذا الباركود مستخدم لصنف آخر', 'r');
    if (!f.barcodes.includes(v)) { f.barcodes.push(v); drawBarcodes(); }
    bcInp.value = '';
  };
  bcInp.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addBarcode(bcInp.value); } });

  /* بناء التعبئة */
    /* بناء التعبئة — أسماء الوحدات من قائمة اختيار (نفس فكرة الشكل العلاجي) */
  const packBox = h('div', { class: 'pack-builder' });
  function unitSelect(u) {
    const names = state.settings.unitNames || [];
    const sel = h('select', { class: 'pname' },
      names.map(n => h('option', { value: n, selected: u.name === n }, n)),
      !names.includes(u.name) ? h('option', { value: u.name, selected: true }, u.name) : null,
      h('option', { value: '__add' }, '＋ إضافة وحدة جديدة…'));
    sel.addEventListener('change', async () => {
      if (sel.value === '__add') {
        const v = await promptBox('إضافة وحدة تعبئة جديدة', { placeholder: 'مثال: علبة' });
        if (v && !names.includes(v)) { state.settings.unitNames.push(v); await DB.put('settings', state.settings); u.name = v; }
      } else u.name = sel.value;
      drawPack(); drawStockUnit(); drawPricePreview();
    });
    return sel;
  }
  function drawPack() {
    packBox.innerHTML = '';
    f.units.forEach((u, i) => {
      const nameI = unitSelect(u);
      const isLast = i === f.units.length - 1;
      const qtyI = h('input', { class: 'pqty', type: 'number', min: 1, value: u.perNext, disabled: isLast, title: 'عدد الوحدات الأصغر داخل هذه الوحدة' });
      qtyI.addEventListener('change', () => { u.perNext = Math.max(1, Math.round(num(qtyI.value)) || 1); drawPricePreview(); });
      packBox.append(h('div', { class: 'pack-row' },
        h('span', { class: 'pnum' }, i + 1), nameI,
        isLast ? h('span', { class: 'parrow' }, 'الوحدة الصغرى (أساس البيع والجرد)')
          : h('span', { class: 'parrow' }, 'تحتوي على'), !isLast ? qtyI : null,
        !isLast ? h('span', { class: 'parrow' }, `من «${f.units[i + 1].name}»`) : null,
                f.units.length > 1 ? h('button', { class: 'pdel', html: icon('trash'), onclick: () => {
          /* ★ حذف تعبئة بلا بقايا: معاملها يندمج في الوحدة الأعلى، والصغرى الجديدة تُصفَّر إلى 1 —
             هكذا يزول أثر التقسيم من الأسعار والمخزون نهائياً */
          if (i > 0) f.units[i - 1].perNext = (f.units[i - 1].perNext || 1) * (f.units[i].perNext || 1);
          f.units.splice(i, 1);
          f.units[f.units.length - 1].perNext = 1;
          drawPack(); drawStockUnit(); drawPricePreview();
        } }) : null));
    });
        packBox.append(h('button', { class: 'pack-add', onclick: () => {
      if (f.units.length >= 4) return toast('الحد الأقصى 4 مستويات تعبئة', 'r');
      if (f.units.length === 1 && f.units[0].name === 'قطعة') f.units[0].name = 'باكيت'; // قطعة ← باكيت تلقائياً عند أول تقسيم
      f.units[f.units.length - 1].perNext = 10;
      f.units.push({ name: 'شريط', perNext: 1 });
      drawPack(); drawStockUnit(); drawPricePreview();
    } }, h('span', { html: icon('plus') }), 'إضافة وحدة أصغر'));
  }

  /* الأسعار */
     /* الأسعار — محرك ديناميكي: صف مستقل لكل وحدة تعبئة.
     تعبئة واحدة = صف واحد (شراء + بيع). تعبئتان = صفان، ثلاث = ثلاثة…
     يُدخَل المستخدم «سعر شراء الكبرى» و«سعر بيع الصغرى» فقط، وكل ما بينهما يُشتق آليًا. */
  const buyInp = h('input', { type: 'number', min: 0, value: f.purchasePriceTop || '', placeholder: '0' });
  const pctInp = h('input', { type: 'number', min: 0, value: existing ? '' : (state.settings.profitPct ?? 30), style: { width: '90px' } });
  const sellInp = h('input', { type: 'number', min: 0, value: f.salePriceBase || '', placeholder: '0' });
  const rowsBox = h('div', { class: 'price-rows' });
  const prevBox = h('div', { class: 'price-preview' });
  function unitF(idx) { let x = 1; for (let i = idx; i < f.units.length; i++) x *= (f.units[i].perNext || 1); return x; }
  function syncFromPct() {
    const buyBase = num(buyInp.value) / (unitF(0) || 1);
    sellInp.value = buyBase ? Math.round(buyBase * (1 + num(pctInp.value) / 100)) : '';
    drawPriceRows();
  }
  function syncFromSell() {
    const buyBase = num(buyInp.value) / (unitF(0) || 1);
    pctInp.value = buyBase && num(sellInp.value) ? Math.round((num(sellInp.value) / buyBase - 1) * 1000) / 10 : pctInp.value;
    drawPriceRows();
  }
  /* يعيد البناء الكامل فقط عند تغيّر عدد/أسماء الوحدات؛ أثناء الكتابة يحدّث القيم المحسوبة فقط فلا يُفقد التركيز */
  let priceSig = null, rowVals = [];
  function drawPriceRows() {
    const sig = f.units.map(u => u.name).join('|');
    const bf = unitF(0) || 1;
    const buyBase = num(buyInp.value) / bf, sellBase = num(sellInp.value);
    const last = f.units.length - 1;
    if (sig !== priceSig) {
      priceSig = sig; rowVals = [];
      rowsBox.innerHTML = '';
      f.units.forEach((u, i) => {
        const buyVal = h('b', { class: 'pq-val' }, '0');
        const sellVal = h('b', { class: 'pq-val' }, '0');
        rowVals.push({ buyVal, sellVal });
        const buyCell = i === 0
          ? h('div', { class: 'pq-cell edit' }, h('label', {}, `سعر شراء الـ«${u.name}»${last ? ' (الوحدة الكبرى)' : ''}`), buyInp)
          : h('div', { class: 'pq-cell' }, h('label', {}, `سعر شراء الـ«${u.name}» — تلقائي`), h('div', { class: 'pq-view' }, buyVal));
        const sellCell = i === last
          ? h('div', { class: 'pq-cell edit' }, h('label', {}, `سعر بيع الـ«${u.name}»${last ? ' (الوحدة الصغرى)' : ''}`),
              h('div', { class: 'input-group' }, sellInp, h('span', { class: 'pq-side' }, 'ربح'), pctInp, h('span', { class: 'pq-side' }, '%')))
          : h('div', { class: 'pq-cell' }, h('label', {}, `سعر بيع الـ«${u.name}» — تلقائي`), h('div', { class: 'pq-view' }, sellVal));
        rowsBox.append(h('div', { class: 'price-row' }, h('span', { class: 'pr-badge' }, u.name), buyCell, sellCell));
      });
    }
    f.units.forEach((u, i) => {
      if (i !== 0)    rowVals[i].buyVal.textContent  = `${fmt(buyBase * unitF(i))} ${cur()}`;
      if (i !== last) rowVals[i].sellVal.textContent = `${fmt(sellBase * unitF(i))} ${cur()}`;
    });
    prevBox.innerHTML = '';
    f.units.forEach((u, i) => {
      prevBox.append(h('span', { class: 'price-chip' }, `${u.name}:`,
        h('b', {}, `شراء ${fmt(buyBase * unitF(i))} • بيع ${fmt(sellBase * unitF(i))}`)));
    });
  }
  const drawPricePreview = drawPriceRows; // نفس الاسم القديم — لا ينكسر أي استدعاء سابق
  buyInp.addEventListener('input', syncFromPct);
  pctInp.addEventListener('input', syncFromPct);
  sellInp.addEventListener('input', syncFromSell);

  function drawStockUnit() {
    stockUnit.innerHTML = '';
    f.units.forEach((u, i) => stockUnit.append(h('option', { value: i }, u.name)));
  }
  /* ★ التعبئة الافتراضية: الوحدة الصغرى (أساس الجرد) + العدد الفعلي المتراكم الحالي */
  function prefillStock() {
    if (!existing) { stockInp.value = ''; return; }
    const idx = f.units.length - 1;
    stockUnit.value = String(idx);
    stockInp.value = String(Math.round((existing.stockBase || 0) * 100) / 100);
  }

  /* مميز */
  const featSw = h('div', { class: 'lux-switch' + (f.featured ? ' on' : ''), onclick: () => { f.featured = !f.featured; featSw.classList.toggle('on', f.featured); } },
    h('span', { class: 'sw' }), h('div', {}, h('b', {}, 'صنف مميز'), h('small', {}, 'يظهر في تبويب المميز بنقطة البيع للوصول السريع')));

  grid.append(
    h('div', { class: 'f-field' }, h('label', {}, 'اسم البراند ', h('span', { class: 'req' }, '*')), nameInp),
    h('div', { class: 'f-field' }, h('label', {}, 'الاسم العلمي (اختياري)'), sciInp),
    h('div', { class: 'f-field' }, h('label', {}, 'الشركة المصنعة ', h('span', { class: 'req' }, '*')), h('div', { style: { position: 'relative' } }, compInp, compSug)),
    h('div', { class: 'f-field' }, h('label', {}, 'البلد المصنع (اختياري)'), countryInp, countryList),
    h('div', { class: 'f-field full' }, h('label', {}, 'الباركودات (يمكن إضافة عدد لا نهائي)'),
      h('div', { class: 'input-group' }, bcInp,
        h('button', { class: 'btn n', onclick: () => addBarcode(bcInp.value) }, h('span', { html: icon('plus') }), 'إضافة'),
        h('button', { class: 'btn b', onclick: () => { const c = genBarcode(); f.barcodes.push(c); drawBarcodes(); toast(`باركود مولّد: ${c}`, 'b'); openBarcodePrint({ ...f, brandName: (nameInp.value || f.brandName || '').trim() }, c); } }, h('span', { html: icon('barcode') }), 'توليد وطباعة')),
      bcList),
    h('div', { class: 'f-field' }, h('label', {}, 'الشكل العلاجي'), formSel),
    h('div', { class: 'f-field' }, h('label', {}, 'الجرعة'), h('div', { class: 'input-group' }, doseInp, doseUnit)),
    h('div', { class: 'f-field' }, h('label', {}, 'تاريخ الانتهاء'), expiryInp),
    h('div', { class: 'f-field' }, h('label', {}, existing ? 'العدد — المخزون الفعلي (قابل للتعديل)' : 'جرد افتتاحي (اختياري)'),
      h('div', { class: 'input-group' }, stockInp, stockUnit),
      h('div', { class: 'f-hint' }, existing
        ? 'هذا هو العدد الفعلي المتراكم (ادخال/تعديل/جرد/شراء ناقص البيع زائد الإرجاع). عدّله مباشرةً وسيُسجَّل الفرق في «حركة المادة» كسطر «تعديل عدد».'
        : 'الكمية الموجودة حالياً في المخزن عند إضافة الصنف (تُسجَّل كرصيد افتتاحي في حركة المادة).')),
    h('div', { class: 'f-field full' }, featSw),
    h('div', { class: 'f-field full' }, h('label', {}, 'التعبئة والوحدات ', h('span', { class: 'req' }, '*')), packBox),
    h('div', { class: 'f-field full' },
      h('label', {}, 'الأسعار ', h('span', { class: 'req' }, '*'), h('span', { class: 'f-hint' }, ' — صف لكل وحدة تعبئة: تُدخِل شراء الكبرى وبيع الصغرى فقط والباقي تلقائي')),
      rowsBox),
  );

  page.append(grid, h('div', { style: { display: 'flex', gap: '10px', marginTop: '6px', paddingBottom: '14px' } },
    h('button', { class: 'btn g big', onclick: saveIt }, h('span', { html: icon('check') }), existing ? 'حفظ التعديلات' : 'حفظ الصنف'),
    h('button', { class: 'btn n', onclick: () => closeTab(tab.id) }, 'إلغاء')));

    async function saveIt() {
    const name = nameInp.value.trim();
    if (!name) return toast('أدخل اسم البراند', 'r');
        f.company = compInp.value.trim();

    f.country = countryInp.value.trim();
    /* ★ حفظ/توحيد الشركة: مقارنة غير حسّاسة لحالة الأحرف والمسافات — فلا يتكرر الاسم ولا يضيع */
    {
      const nm = f.company.trim();
      const ex = companies.find(c => c.name.trim().toLowerCase() === nm.toLowerCase());
      if (ex) {
        if (nm !== ex.name) ex.name = nm;
        if (f.country && ex.country !== f.country) ex.country = f.country;
      } else {
        companies.push({ name: nm, country: f.country || '' });
      }
      await save('settings', state.settings);
      drawCountryList();
    }
    if (!f.barcodes.length) f.barcodes.push(genBarcode());
    if (!num(buyInp.value)) return toast('أدخل سعر الشراء', 'r');
        if (f.company) {
      const nm = f.company.trim();
      const ex = companies.find(c => c.name.trim().toLowerCase() === nm.toLowerCase());
      if (ex) {
        if (nm !== ex.name) ex.name = nm;
        if (f.country && ex.country !== f.country) ex.country = f.country;
      } else {
        companies.push({ name: nm, country: f.country || '' });
      }
      await save('settings', state.settings);
      drawCountryList();
    }
    if (!num(sellInp.value)) return toast('أدخل سعر البيع', 'r');
    f.brandName = name; f.scientificName = sciInp.value.trim();
    f.form = formSel.value === '__add' ? f.form : formSel.value;
    f.dose = doseInp.value ? `${doseInp.value}${doseUnit.value}` : '';
    f.expiry = expiryInp.value;
    f.purchasePriceTop = num(buyInp.value);
    f.salePriceBase = num(sellInp.value);
    f.units = f.units.filter(u => u.name.trim());
    if (existing) {
      const idx = +stockUnit.value || 0;
      const factor = unitF(idx) || 1;
      f.stockLog = Array.isArray(f.stockLog) ? f.stockLog : [];
            if (existing.brandName !== name) f.stockLog.push({ ts: Date.now(), kind: 'rename', delta: 0,
        note: `${existing.brandName} ← ${name}`, empId: me().id, empName: me().name });
      if (stockInp.value !== '') {
        /* ★ «العدد» يضبط المخزون مباشرةً (لا يضيف فوقه) ويُسجّل الفرق فقط */
        const target = Math.round(num(stockInp.value) * factor * 100) / 100;
        const delta  = Math.round((target - (existing.stockBase || 0)) * 100) / 100;
        if (delta !== 0) f.stockLog.push({ ts: Date.now(), kind: 'adjust', delta,
          note: `تعديل العدد إلى ${num(stockInp.value)} ${f.units[idx] ? f.units[idx].name : ''}`,
          empId: me().id, empName: me().name });
        f.stockBase = target;
      } else {
        f.stockBase = existing.stockBase || 0;
      }
      f.id = existing.id; f.createdAt = existing.createdAt;
    } else {
      f.id = uid(); f.createdAt = Date.now();
      const idx = +stockUnit.value || 0;
      f.stockBase = num(stockInp.value) * unitF(idx);
      f.stockLog = f.stockBase
        ? [{ ts: Date.now(), kind: 'opening', delta: f.stockBase, note: 'جرد افتتاحي', empId: me().id, empName: me().name }]
        : [];
    }
    await save('products', f);
    syncProductEverywhere(f);
    toast(existing ? 'تم حفظ التعديلات' : `تمت إضافة «${f.brandName}»`);
    if (P.returnTab) {
      const rt = tabs.find(t => t.id === P.returnTab);
      if (rt && (rt.type === 'purchase' || rt.type === 'pos')) {
        if (!P.editOnly && rt.type === 'purchase') addPurchaseItem(rt, f, 1);
        closeTab(tab.id); activateTab(rt.id); renderSideNav(); return;
      }
    }
    if (P.onSavedGo) { closeTab(tab.id); openTab(P.onSavedGo); renderSideNav(); return; }
    if (existing) closeTab(tab.id); else { tab.state.form = null; renderTabContent(tab); }
    renderSideNav();
  }
  tab.el.append(page);
    drawPack(); drawStockUnit(); prefillStock(); drawBarcodes(); drawPricePreview();
  setTimeout(() => nameInp.focus(), 80);
}

/* ───────────────────────── 15) قائمة الشراء ───────────────────────── */
function renderPurchase(tab) {
  const st = tab.state;
  st.items = st.items || [];  // [{productId,name,unitIdx,qty,buyPrice,expiry}]
  st.discount = st.discount || 0;
  const page = h('div', { class: 'pos-layout' });
  const center = h('div', { class: 'pos-center' });

  /* رأس القائمة: المذخر + رقم القائمة */
  const supSel = h('select', {}, h('option', { value: '' }, '— اختر المذخر —'),
    state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: st.supplierId === s.id }, s.name)));
  supSel.addEventListener('change', () => st.supplierId = supSel.value || null);
  const listNum = h('input', { value: st.listNum || (state.purchases.length + 1), type: 'number', min: 1, style: { width: '110px' } });
  listNum.addEventListener('change', () => st.listNum = num(listNum.value));
  center.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'اسم المذخر'), supSel,
            h('button', { class: 'icon-btn edit', title: 'إضافة مذخر', html: icon('plus'), onclick: () => openAddSupplierModal(() => renderTabContent(tab)) })),
    h('div', { class: 'f-group' }, h('label', {}, 'رقم القائمة'), listNum),
    h('div', { class: 'spacer' }),
    h('button', { class: 'mini-btn blue', style: { flex: 'none', padding: '8px 16px' }, onclick: () => openTab('scanner', { returnTab: tab.id }) },
      h('span', { html: icon('camera') }), 'قراءة فاتورة ورقية بالصورة')));

  /* محرك البحث / الباركود */
  const sInput = h('input', { placeholder: 'أدخل باركود الصنف أو ابحث بالاسم…', autocomplete: 'off' });
  const sugBox = h('div', { class: 'suggestions' });
  let sugItems = [];
  sInput.addEventListener('input', () => {
    const q = sInput.value;
    sugItems = searchProducts(q);
    sugBox.innerHTML = '';
    if (!q.trim()) { sugBox.classList.remove('show'); return; }
    if (!sugItems.length) sugBox.append(h('div', { class: 'sug-empty' }, 'غير موجود — اضغط Enter لإضافته كصنف جديد'));
    else sugItems.forEach(p => sugBox.append(h('div', { class: 'sug-item', onclick: () => pick(p) },
      h('span', { class: 'sug-ic', html: icon('pill') }),
      h('div', { class: 'sug-name' }, p.brandName, coTag(p), h('small', {}, `${p.form || ''} ${p.dose || ''}`)),
      h('span', { class: 'sug-price' }, `شراء ${fmt(costPerUnit(p, 0))} / ${bigUnitName(p)}`))));
    sugBox.classList.add('show');
  });
  sInput.addEventListener('keydown', async e => {
    if (e.key !== 'Enter') return;
    const q = sInput.value.trim();
    if (!q) return;
    const exact = state.products.find(p => !p.deleted && (p.barcodes || []).some(b => b === q));
    if (exact) pick(exact);
    else if (sugItems.length === 1) pick(sugItems[0]);
    else {
      sugBox.classList.remove('show');
      const yes = await confirmBox(`الصنف «${q}» غير متوفر في النظام. هل تريد إدخاله؟`, { okLabel: 'نعم، إدخاله', icon: 'plus' });
      if (yes) openTab('product', { barcode: q, returnTab: tab.id, supplierId: st.supplierId });
    }
  });
  function pick(p) {
    addPurchaseItem(tab, p, 1);
    sInput.value = ''; sugBox.classList.remove('show'); sInput.focus();
  }
  center.append(h('div', { class: 'search-engine' },
    h('div', { class: 'search-box' }, h('span', { html: icon('barcode') }), sInput,
      h('span', { class: 'search-hint' }, 'باركود ← إدخال مباشر')), sugBox));

  /* جدول الأصناف */
  const cartWrap = h('div', { class: 'cart-wrap' });
  st.renderItems = () => {
    cartWrap.innerHTML = '';
    if (!st.items.length) {
      cartWrap.append(h('div', { class: 'cart-empty' }, h('span', { html: icon('purchase') }), h('p', {}, 'أدخل باركود الأصناف لبناء قائمة الشراء')));
      return;
    }
    const tbody = h('tbody');
    st.items.forEach((it, i) => {
      const p = findProd(it.productId);
      const totalTd = h('td', { class: 'td-num td-total' }, fmt(it.buyPrice * it.qty));
      const live = () => { totalTd.textContent = fmt(it.buyPrice * it.qty); drawTotals(); };
      const boxCss = { border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 };
      const rm = h('button', { class: 'icon-btn del', title: 'إزالة من القائمة', html: icon('close'),
        onclick: () => { st.items.splice(i, 1); st.renderItems(); drawTotals(); } });
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, it.name, h('small', {}, p ? `${p.form || ''} ${p.dose || ''}` : '')),
        h('td', {}, p ? (() => {
          const sel = h('select', { class: 'unit-select' }, p.units.map((u, ui) => h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => { it.unitIdx = +sel.value; it.buyPrice = Math.round(costPerUnit(p, it.unitIdx) * 100) / 100; st.renderItems(); drawTotals(); });
          return sel;
        })() : it.unitName || ''),
        h('td', {}, (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 1, style: { ...boxCss, width: '70px' } });
          const apply = () => { it.qty = Math.max(1, num(q.value) || 1); live(); };
          q.addEventListener('input', apply); q.addEventListener('change', apply);
          return q;
        })()),
        h('td', {}, (() => {
          const pr = h('input', { type: 'number', value: it.buyPrice, min: 0, step: 'any', style: { ...boxCss, width: '90px' } });
          const apply = () => { it.buyPrice = num(pr.value); live(); };
          pr.addEventListener('input', apply); pr.addEventListener('change', apply);
          return pr;
        })()),
        h('td', {}, (() => {
          const ex = h('input', { type: 'month', value: it.expiry || (p ? p.expiry : '') || '', style: { border: '1px solid var(--line)', borderRadius: '8px', padding: '4px 6px', fontWeight: 800, fontSize: '12.5px' } });
          ex.addEventListener('change', () => it.expiry = ex.value);
          return ex;
        })()),
        totalTd,
        h('td', {}, p ? productActions(p, tab, rm) : h('div', { class: 'row-act' }, rm)),
      ));
    });
    cartWrap.append(h('div', { class: 'tbl-scroll' },
      h('table', { class: 'tbl' },
        h('thead', {},
          h('tr', {},
            h('th', {}, 'ت'),
            h('th', {}, 'المنتج'),
            h('th', {}, 'الوحدة'),
            h('th', {}, 'العدد'),
            h('th', {}, 'سعر الشراء'),
            h('th', {}, 'الإكسباير'),
            h('th', {}, 'المجموع'),
            h('th', {}, 'إجراء'))),
        tbody)));
  };

  /* التذييل */
  const totalEl = h('div', { class: 'tval' }, h('span', {}, '0'), ' ', h('small', {}, cur()));
  const discInp = h('input', { type: 'number', min: 0, placeholder: '0', value: st.discount || '' });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); drawTotals(); });
  st.drawTotals = drawTotals;
  function drawTotals() {
    const t = st.items.reduce((s, it) => s + it.buyPrice * it.qty, 0);
    animNum(totalEl.firstChild, Math.max(0, t - st.discount));
  }
  const footer = h('div', { class: 'pos-footer' },
    h('div', { class: 'totals-row' },
      h('div', { class: 'total-card' }, h('label', {}, 'خصم القائمة'), h('div', { class: 'discount-wrap' }, discInp)),
      h('div', { class: 'total-card grand' }, h('label', {}, 'إجمالي قائمة الشراء'), totalEl)),
    h('div', { class: 'pay-row' },
      h('button', { class: 'pay-btn cash', onclick: () => savePurchaseModal(tab) }, h('span', { html: icon('check') }), 'حفظ قائمة الشراء')));

  center.append(cartWrap);
  /* الجانب: قوائم الشراء السابقة */
  const side = h('div', { class: 'pos-side' });
  side.append(h('div', { class: 'side-tabs' }, h('div', { class: 'side-tab active' }, 'قوائم الشراء السابقة')));
  const sideBody = h('div', { class: 'side-body' });
    state.purchases.filter(p => p.type === 'return' && !p.deleted).sort((a, b) => b.ts - a.ts).slice(0, 30).forEach(pu =>
    sideBody.append(h('div', { class: 'inv-mini', onclick: () => openTab('editpurch', { purchaseId: pu.id, readonly: true }) },
      h('div', { class: 'im-top' }, h('span', {}, pu.supplierName), h('b', {}, `${fmt(pu.total)} ${cur()}`)),
      h('div', { class: 'im-sub' }, h('span', {}, `قائمة رقم ${pu.listNum} • ${fmtDate(pu.ts)}`),
        h('span', { class: 'badge ' + (pu.pay === 'cash' ? 'g' : 'r') }, pu.pay === 'cash' ? 'كاش' : 'آجل')))));
  if (!sideBody.children.length) sideBody.append(h('div', { class: 'empty-note' }, 'لا قوائم شراء سابقة'));
  side.append(sideBody);
  page.append(h('div', { style: { flex: 1, display: 'flex', minHeight: 0 } }, center, side), footer);
  tab.el.append(page);
  st.renderItems(); drawTotals();
  setTimeout(() => sInput.focus(), 60);
}
const parsePrice = v => {
  const n = parseFloat(String(v == null ? '' : v)
    .replace(/[\u0660-\u0669]/g, d => d.charCodeAt(0) - 0x0660).replace(/\u066B/g, '.').replace(/[\u066C,\s]/g, ''));
  return isFinite(n) && n > 0 ? n : 0;
};
function addPurchaseItem(tab, p, qty = 1, opts = {}) {
  const st = tab.state;
  st.items = st.items || [];
  qty = num(qty) > 0 ? num(qty) : 1;
  const price = parsePrice(opts.price);
  const ex = st.items.find(it => it.productId === p.id && it.unitIdx === 0);
  if (ex) { ex.qty += qty; if (price) ex.buyPrice = price; if (opts.expiry) ex.expiry = opts.expiry; }
  else st.items.push({ productId: p.id, name: p.brandName, unitIdx: 0, qty,
    buyPrice: price || costPerUnit(p, 0) || 0,
    expiry: opts.expiry || p.expiry || '' });
  if (st.renderItems) st.renderItems();
  if (st.drawTotals) st.drawTotals();
  if (!opts.silent) toast(`أُضيف «${p.brandName}» للقائمة`, 'b');
}
async function savePurchaseModal(tab) {
  const st = tab.state;
  if (!st.items || !st.items.length) return toast('القائمة فارغة', 'r');
  if (!st.supplierId) return toast('اختر المذخر أولاً', 'r');
  const sup = findSup(st.supplierId);
  const total = st.items.reduce((s, it) => s + it.buyPrice * it.qty, 0);
  const discPctInp = h('input', { type: 'number', min: 0, max: 100, value: total ? Math.round(st.discount / total * 1000) / 10 : 0, style: { width: '90px' } });
  const m = openModal({
    title: 'طريقة تسديد قائمة الشراء', icon: 'cash',
    body: h('div', {},
      h('div', { class: 'sum-card n', style: { marginBottom: '14px' } }, h('label', {}, `إجمالي القائمة للمذخر «${sup.name}»`), h('b', {}, animSpan(total, ' ' + cur()))),
      h('div', { class: 'f-field' }, h('label', {}, 'خصم المذخر (نسبة %)'), h('div', { class: 'input-group' }, discPctInp,
        h('span', { style: { alignSelf: 'center', fontWeight: 900 } }, `% ≈ ${fmt(total * num(discPctInp.value) / 100)} ${cur()}`)))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'آجل (دين متراكم)', cls: 'r', icon: 'clock', big: true, onClick: c => { c(); finalizePurchase(tab, 'credit', total * num(discPctInp.value) / 100); } },
      { label: 'كاش مباشر', cls: 'g', icon: 'cash', big: true, onClick: c => { c(); finalizePurchase(tab, 'cash', total * num(discPctInp.value) / 100); } },
    ],
  });
}
async function finalizePurchase(tab, pay, discount) {
  const st = tab.state;
  const sup = findSup(st.supplierId);
  const acc = me();
  const ts = Date.now();
  const items = st.items.map(it => {
    const p = findProd(it.productId);
    return { ...it, unitName: p ? p.units[it.unitIdx].name : '', qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.buyPrice * it.qty };
  });
  const total = Math.max(0, items.reduce((s, it) => s + it.total, 0) - discount);
  if (pay === 'credit') sup.debt = (sup.debt || 0) + total;
  sup.lastPurchase = { amount: total, ts };
  const pu = {
    id: uid(), type: 'purchase', version: 1, versions: [],
    supplierId: sup.id, supplierName: sup.name, listNum: st.listNum || (state.purchases.length + 1),
    items, discount, total, pay, debtAfter: sup.debt || 0,
    employeeId: acc.id, employeeName: acc.name,
    ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
  };
  await save('purchases', pu);
  await save('suppliers', sup);
  for (const it of items) {  // رفع المخزون + تحديث سعر الشراء والإكسباير
    const p = findProd(it.productId);
    if (p) {
      p.stockBase = (p.stockBase || 0) + it.qtyBase;
      if (it.unitIdx === 0 && it.buyPrice) p.purchasePriceTop = it.buyPrice;
      if (it.expiry) p.expiry = it.expiry;
      await save('products', p);
    }
  }
  st.items = []; st.discount = 0; st.listNum = null; st.supplierId = null;
  renderTabContent(tab);
  renderSideNav();
  toast(`حُفظت قائمة الشراء — ${fmt(total)} ${cur()} ${pay === 'credit' ? '(دين متراكم)' : '(كاش)'}`);
}

/* ───────────────────────── 16) تقرير المبيعات ───────────────────────── */
function renderSalesReport(tab) {
  const st = tab.state;
  st.f = st.f || { customer: '', employee: me() ? me().id : '', from: dateStr(), to: dateStr(), type: '', sortKey: 'ts', sortDir: -1 };
  const page = h('div', { class: 'page' });

  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });

  const applied = h('span', { class: 'badge amber', style: { flex: 'none' } }, 'الفلاتر غير مطبَّقة');
  const pp = () => { applied.className = 'badge amber'; applied.textContent = 'الفلاتر غير مطبَّقة — اضغط «بحث / تحديث»'; };

  /* الفلاتر — لا تُنفَّذ إلا بضغط «بحث / تحديث» */
  const custSel = h('select', {}, h('option', { value: '' }, 'الكل'),
    state.customers.map(c => h('option', { value: c.id, selected: st.f.customer === c.id }, c.name)));
  custSel.addEventListener('change', () => { st.f.customer = custSel.value; pp(); });
  const empSel = h('select', {}, h('option', { value: '' }, 'الكل'),
    state.accounts.filter(a => !a.deleted).map(a => h('option', { value: a.id, selected: st.f.employee === a.id }, a.name)));
  empSel.addEventListener('change', () => { st.f.employee = empSel.value; pp(); });
  const fromI = h('input', { type: 'date', value: st.f.from });
  const toI = h('input', { type: 'date', value: st.f.to });
  fromI.addEventListener('change', () => { st.f.from = fromI.value; pp(); });
  toI.addEventListener('change', () => { st.f.to = toI.value; pp(); });
  const typeSel = h('select', {}, h('option', { value: '' }, 'الكل'), h('option', { value: 'sale' }, 'بيع'), h('option', { value: 'return' }, 'استرجاع بيع'));
  typeSel.value = st.f.type;
  typeSel.addEventListener('change', () => { st.f.type = typeSel.value; pp(); });

  const searchBtn = h('button', { class: 'btn g', style: { flex: 'none' }, onclick: () => draw() },
    h('span', { html: icon('search') }), 'بحث / تحديث');
  const quick = (label, from, to) => h('button', { class: 'mini-btn blue', style: { flex: 'none' },
    onclick: () => { st.f.from = from; st.f.to = to; fromI.value = from; toI.value = to; draw(); } }, label);

  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('report') }), 'تقرير المبيعات'),
    h('div', { class: 'spacer' }),
    applied, searchBtn,
    quick('اليوم', dateStr(), dateStr()),
    quick('آخر 30 يوم', dateStr(Date.now() - 30 * 864e5), dateStr()),
        h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: () => { [st.f.from, st.f.to] = monthRange(); fromI.value = st.f.from; toI.value = st.f.to; draw(); } }, 'الشهر الحالي'),
    h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: () => {
      st.f = { customer: '', employee: '', from: '', to: '', type: '', sortKey: 'ts', sortDir: -1 };
      custSel.value = ''; empSel.value = ''; fromI.value = ''; toI.value = ''; typeSel.value = '';
      draw();
    } }, 'الكل من البداية')));
  page.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'الزبون'), custSel),
    h('div', { class: 'f-group' }, h('label', {}, 'الموظف'), empSel),
    h('div', { class: 'f-group' }, h('label', {}, 'من'), fromI, h('label', {}, 'إلى'), toI),
    h('div', { class: 'f-group' }, h('label', {}, 'نوع العملية'), typeSel)));
  page.append(bodyBox, footBox);

  const COLS = [
    ['type', 'نوع العملية'], ['employeeName', 'الموظف'], ['customerName', 'الزبون'],
    ['date', 'التاريخ'], ['time', 'الوقت'], ['pay', 'نوع الدفع'], ['cost', 'التكلفة'],
    ['subtotal', 'البيع'], ['profit', 'الربح'], ['discount', 'الخصم'], ['net', 'صافي البيع'], [null, 'تعديل'],
  ];

  /* ★★ الإصلاح الجذري: كان يقرأ state.purchases ويصفّي بمفتاح مورد. الآن يقرأ state.sales فعلاً. */
  function filtered() {
    return state.sales.filter(s =>
      (!st.f.customer || s.customerId === st.f.customer) &&
      (!st.f.employee || s.employeeId === st.f.employee) &&
      (!st.f.from || s.date >= st.f.from) && (!st.f.to || s.date <= st.f.to) &&
      (!st.f.type || s.type === st.f.type)
    ).sort((a, b) => {
      const k = st.f.sortKey; const va = a[k], vb = b[k];
      if (typeof va === 'string' || typeof vb === 'string')
        return String(va || '').localeCompare(String(vb || ''), 'ar') * st.f.sortDir;
      return ((va || 0) - (vb || 0)) * st.f.sortDir;
    });
  }

  function draw() {
    const rows = filtered();
    bodyBox.innerHTML = '';
    const thead = h('tr', {}, COLS.map(([k, label]) =>
      h('th', { class: k ? 'sortable' : '', onclick: k ? () => { if (st.f.sortKey === k) st.f.sortDir *= -1; else { st.f.sortKey = k; st.f.sortDir = -1; } draw(); } : null },
        label, st.f.sortKey === k ? h('span', { class: 'sort-arw' }, st.f.sortDir === -1 ? ' ▼' : ' ▲') : null)));
    const tbody = h('tbody');
    rows.forEach(s => tbody.append(h('tr', {},
      h('td', {}, h('span', { class: 'badge ' + (s.type === 'sale' ? 'g' : 'r') }, s.type === 'sale' ? 'بيع' : 'استرجاع'),
        s.version > 1 ? h('span', { class: 'badge n', title: 'عدد التعديلات' }, `ع${s.version}`) : null),
      h('td', {}, s.employeeName), h('td', {}, s.customerName || 'زبون نقدي'),
      h('td', { class: 'mono' }, fmtDate(s.ts)), h('td', { class: 'mono' }, fmtTime(s.ts)),
      h('td', {}, h('span', { class: 'badge ' + (s.pay === 'cash' ? 'g' : s.pay === 'electronic' ? 'b' : 'r') },
        s.pay === 'cash' ? 'كاش' : s.pay === 'electronic' ? 'إلكتروني' : 'آجل')),
      h('td', { class: 'td-num td-cost' }, fmt(s.cost)),
      h('td', { class: 'td-num td-sale' }, fmt(s.subtotal)),
      h('td', { class: 'td-num', style: { color: s.profit >= 0 ? 'var(--green)' : 'var(--red)' } }, fmt(s.profit)),
      h('td', { class: 'td-num', style: { color: 'var(--red)' } }, fmt(s.discount)),
      h('td', { class: 'td-num td-total', style: { fontSize: '16px' } }, fmt(s.net)),
      h('td', {}, h('button', { class: 'icon-btn edit', title: 'تعديل القائمة', html: icon('edit'), onclick: () => openTab('editsale', { saleId: s.id }) })),
    )));
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' }, h('thead', {}, thead), tbody)));
    if (!rows.length) bodyBox.append(h('div', { class: 'empty-note' }, 'لا نتائج ضمن الفلاتر المحددة'));

    applied.className = 'badge g';
    applied.textContent = `مطبَّق — ${rows.length} سجل`;

    /* الإجماليات — الإلكتروني منفصل، الآجل خارج الدخل */
    const sales = rows.filter(s => s.type === 'sale'), rets = rows.filter(s => s.type === 'return');
    const cashNet = sales.filter(s => s.pay === 'cash').reduce((x, s) => x + s.net, 0) - rets.filter(s => s.pay === 'cash').reduce((x, s) => x + s.net, 0);
    const elecNet = sales.filter(s => s.pay === 'electronic').reduce((x, s) => x + s.net, 0) - rets.filter(s => s.pay === 'electronic').reduce((x, s) => x + s.net, 0);
    const credNet = sales.filter(s => s.pay === 'credit').reduce((x, s) => x + s.net, 0) - rets.filter(s => s.pay === 'credit').reduce((x, s) => x + s.net, 0);
    const tCost = rows.reduce((x, s) => x + (s.type === 'sale' ? s.cost : -s.cost), 0);
    const tSale = rows.reduce((x, s) => x + (s.type === 'sale' ? s.subtotal : -s.subtotal), 0);
    const tDisc = rows.reduce((x, s) => x + s.discount, 0);
    const tRet = rets.reduce((x, s) => x + s.net, 0);
    footBox.innerHTML = '';
    footBox.append(
      h('div', { class: 'sum-card n' }, h('label', {}, 'التكلفة الكلية'), h('b', {}, animSpan(tCost))),
      h('div', { class: 'sum-card r' }, h('label', {}, 'مجموع المرتجعات'), h('b', {}, animSpan(tRet))),
      h('div', { class: 'sum-card b' }, h('label', {}, 'البيع الكلي (قبل الخصم)'), h('b', {}, animSpan(tSale))),
      h('div', { class: 'sum-card r' }, h('label', {}, 'الخصم الكلي'), h('b', {}, animSpan(tDisc))),
      h('div', { class: 'sum-card g' }, h('label', {}, 'كاش'), h('b', {}, animSpan(cashNet))),
      h('div', { class: 'sum-card b' }, h('label', {}, 'إلكتروني (منفصل)'), h('b', {}, animSpan(elecNet))),
      h('div', { class: 'sum-card r' }, h('label', {}, 'آجل (خارج الدخل)'), h('b', {}, animSpan(credNet))),
      h('div', { class: 'sum-card big' }, h('label', {}, 'صافي الدخل (كاش + إلكتروني)'), h('b', {}, animSpan(cashNet + elecNet, ' ' + cur()))));
  }
  draw();
  tab.el.append(page);
}

/* ───────────────────────── 17) تعديل قائمة بيع (نظام النسخ) ───────────────────────── */
function renderEditSale(tab) {
  const sale = state.sales.find(s => s.id === tab.props.saleId);
  if (!sale) { tab.el.append(h('div', { class: 'empty-note' }, 'القائمة غير موجودة')); return; }
  const st = tab.state;
  st.viewVer = st.viewVer || sale.version; // الافتراضي: آخر نسخة
  const isLatest = st.viewVer === sale.version;
  const snap = isLatest ? sale : sale.versions[st.viewVer - 1];
  if (!st.editItems || st.savedFor !== sale.version) {
    st.editItems = JSON.parse(JSON.stringify(snap.items));
    st.discount = snap.discount;
    st.pay = snap.pay; st.customerId = snap.customerId;
    st.savedFor = null;
  }
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('edit') }),
      `تعديل قائمة بيع — ${fmtDate(sale.ts)} ${fmtTime(sale.ts)}`),
    h('span', { class: 'badge n' }, `الموظف الأصلي: ${sale.employeeName}`),
    h('div', { class: 'spacer' }),
    h('div', { class: 'ver-pills' },
      h('span', { class: 'ver-note' }, 'النسخة:'),
      ...Array.from({ length: sale.version }, (_, i) => i + 1).map(v =>
        h('button', { class: 'ver-pill' + (v === st.viewVer ? ' cur' : ''), onclick: () => { st.viewVer = v; st.savedFor = null; renderTabContent(tab); } }, v)))),
  );
  if (!isLatest)
    page.append(h('div', { class: 'readonly-banner' }, h('span', { html: icon('lock') }),
      `أنت تعرض النسخة رقم ${st.viewVer} (قراءة فقط) — التعديل يتم دائماً على آخر نسخة (رقم ${sale.version})`));

  const center = h('div', { class: 'pos-center', style: { padding: 0 } });
  if (isLatest) {
    const sInput = h('input', { placeholder: 'أضف صنفاً للقائمة…', autocomplete: 'off' });
    const sugBox = h('div', { class: 'suggestions' });
    let sugItems = [];
    sInput.addEventListener('input', () => {
      sugItems = searchProducts(sInput.value);
      sugBox.innerHTML = '';
      if (!sInput.value.trim()) { sugBox.classList.remove('show'); return; }
      sugItems.forEach(p => sugBox.append(h('div', { class: 'sug-item', onclick: () => {
        st.editItems.push({ productId: p.id, name: p.brandName, unitIdx: p.units.length - 1, unitName: p.units[p.units.length - 1].name, qty: 1, cost: costPerUnit(p, p.units.length - 1), sale: salePerUnit(p, p.units.length - 1) });
        sInput.value = ''; sugBox.classList.remove('show'); drawItems(); drawTotals();
      } }, h('span', { class: 'sug-ic', html: icon('pill') }), h('div', { class: 'sug-name' }, p.brandName, coTag(p)), h('span', { class: 'sug-price' }, fmt(salePerUnit(p, p.units.length - 1))))));
      sugBox.classList.toggle('show', !!sugItems.length);
    });
    center.append(h('div', { class: 'search-engine' }, h('div', { class: 'search-box' }, h('span', { html: icon('search') }), sInput), sugBox));
  }
  const itemsBox = h('div', { class: 'cart-wrap', style: { flex: 'none', maxHeight: '46vh' } });
  function drawItems() {
    itemsBox.innerHTML = '';
    const tbody = h('tbody');
    st.editItems.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, it.name),
        h('td', {}, isLatest && p ? (() => {
          const sel = h('select', { class: 'unit-select' }, p.units.map((u, ui) => h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => { it.unitIdx = +sel.value; it.sale = salePerUnit(p, it.unitIdx); it.cost = costPerUnit(p, it.unitIdx); drawItems(); drawTotals(); });
          return sel;
        })() : (it.unitName || '')),
        h('td', {}, isLatest ? (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 0.5, style: { width: '70px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          q.addEventListener('change', () => { it.qty = Math.max(0.5, num(q.value) || 1); drawTotals(); });
          return q;
        })() : fmt(it.qty)),
        h('td', { class: 'td-num td-sale' }, fmt(it.sale)),
        h('td', { class: 'td-num td-total' }, fmt(it.sale * it.qty)),
        isLatest ? h('td', {}, h('button', { class: 'icon-btn del', html: icon('trash'), onclick: () => { st.editItems.splice(i, 1); drawItems(); drawTotals(); } })) : h('td', {}, ''),
      ));
    });
    itemsBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'سعر البيع'), h('th', {}, 'المجموع'), h('th', {}, ''))), tbody)));
  }
  const netEl = h('b', {}, '0');
  const discInp = h('input', { type: 'number', min: 0, value: st.discount, disabled: !isLatest, style: { width: '100px', border: '1.5px solid var(--line)', borderRadius: '10px', padding: '7px', fontWeight: 900, textAlign: 'center' } });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); drawTotals(); });
  const paySel = h('select', { class: 'unit-select', disabled: !isLatest },
    h('option', { value: 'cash', selected: st.pay === 'cash' }, 'كاش'),
    h('option', { value: 'electronic', selected: st.pay === 'electronic' }, 'إلكتروني'),
    h('option', { value: 'credit', selected: st.pay === 'credit' }, 'آجل'));
  paySel.addEventListener('change', () => st.pay = paySel.value);
  const custSel = h('select', { class: 'unit-select', disabled: !isLatest },
    h('option', { value: '' }, 'زبون نقدي'), state.customers.map(c => h('option', { value: c.id, selected: st.customerId === c.id }, c.name)));
  custSel.addEventListener('change', () => st.customerId = custSel.value || null);
  function drawTotals() {
    const sub = st.editItems.reduce((s, it) => s + it.sale * it.qty, 0);
    animNum(netEl, Math.max(0, sub - st.discount), ' ' + cur());
  }
  center.append(itemsBox,
    h('div', { class: 'filter-bar', style: { marginTop: '12px' } },
      h('div', { class: 'f-group' }, h('label', {}, 'الخصم'), discInp),
      h('div', { class: 'f-group' }, h('label', {}, 'نوع الدفع'), paySel),
      h('div', { class: 'f-group' }, h('label', {}, 'الزبون'), custSel),
      h('div', { class: 'spacer' }),
      h('div', { class: 'f-group' }, h('label', {}, 'الصافي بعد التعديل'), netEl)));
  if (isLatest) {
    center.append(h('div', { style: { display: 'flex', gap: '10px', marginTop: '12px' } },
      h('button', { class: 'btn g big', onclick: saveEdit }, h('span', { html: icon('check') }), 'حفظ التعديل (نسخة جديدة)'),
      sale.type === 'sale' ? h('button', { class: 'btn r', onclick: makeReturn }, h('span', { html: icon('refresh') }), 'استرجاع القائمة كاملة') : null));
  }
  page.append(center);
  tab.el.append(page);
  drawItems(); drawTotals();

  async function saveEdit() {
    if (!st.editItems.length) return toast('لا يمكن حفظ قائمة فارغة', 'r');
    // 1) خزّن النسخة الحالية في الأرشيف (لا تُمحى أبداً)
    sale.versions.push({ items: JSON.parse(JSON.stringify(sale.items)), subtotal: sale.subtotal, discount: sale.discount, net: sale.net, cost: sale.cost, profit: sale.profit, pay: sale.pay, customerId: sale.customerId, customerName: sale.customerName });
    // 2) صحّح المخزون: أعد القديم ثم اخصم الجديد
    for (const it of sale.items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) + it.qtyBase; } }
    const items = st.editItems.map(it => {
      const p = findProd(it.productId);
      return { ...it, unitName: p ? p.units[it.unitIdx].name : it.unitName, qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.sale * it.qty };
    });
    for (const it of items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) - it.qtyBase; await save('products', p); } }
    // 3) حدّث القائمة (نفس الوقت والتاريخ والموقع)
    sale.items = items;
    sale.subtotal = items.reduce((s, it) => s + it.total, 0);
    sale.discount = st.discount;
    sale.net = Math.max(0, sale.subtotal - st.discount);
    sale.cost = items.reduce((s, it) => s + it.cost * it.qty, 0);
    sale.profit = sale.net - sale.cost;
    sale.pay = st.pay;
    sale.customerId = st.customerId;
    sale.customerName = st.customerId ? (findCust(st.customerId) || {}).name : 'زبون نقدي';
    sale.version += 1;
    sale.editedBy = me().name; sale.editedAt = Date.now();
    await save('sales', sale);
    st.savedFor = sale.version;
    toast(`حُفظت النسخة ${sale.version} — القائمة بقت بوقتها الأصلي`);
    closeTab(tab.id);
  }
  async function makeReturn() {
    const yes = await confirmBox('سيتم إنشاء قائمة استرجاع كاملة لهذه الفاتورة وإعادة الأصناف للمخزون. متابعة؟', { danger: true, okLabel: 'استرجاع', icon: 'refresh' });
    if (!yes) return;
    const ts = Date.now();
    const acc = me();
    const ret = {
      id: uid(), type: 'return', version: 1, versions: [], originalId: sale.id,
      items: JSON.parse(JSON.stringify(sale.items)), subtotal: sale.subtotal, discount: sale.discount,
      net: sale.net, cost: sale.cost, profit: -sale.profit,
      pay: sale.pay, customerId: sale.customerId, customerName: sale.customerName,
      employeeId: acc.id, employeeName: acc.name, ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
    };
    await save('sales', ret);
    for (const it of sale.items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) + it.qtyBase; await save('products', p); } }
    toast('تم إنشاء قائمة الاسترجاع وإعادة المخزون', 'b');
    closeTab(tab.id);
  }
}

/* ───────────────────────── 18) تقرير المشتريات ───────────────────────── */
function renderPurchaseReport(tab) {
  const st = tab.state;
    st.f = st.f || { supplier: '', employee: '', from: dateStr(), to: dateStr(), type: '', sortKey: 'ts', sortDir: 1 }; // يفتح على اليوم مباشرة
  const page = h('div', { class: 'page' });
    page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('history') }), 'تقرير المشتريات'),
    h('div', { class: 'spacer' }),
    h('button', { class: 'btn g', style: { flex: 'none' }, onclick: () => draw() }, h('span', { html: icon('search') }), 'بحث / تحديث'),
        h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: () => { st.f.from = dateStr(); st.f.to = dateStr(); fromI.value = st.f.from; toI.value = st.f.to; draw(); } }, 'اليوم'),
    h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: () => { st.f.from = dateStr(Date.now() - 30 * 864e5); st.f.to = dateStr(); fromI.value = st.f.from; toI.value = st.f.to; draw(); } }, 'آخر 30 يوم'),
    h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: () => { [st.f.from, st.f.to] = monthRange(); fromI.value = st.f.from; toI.value = st.f.to; draw(); } }, 'الشهر الحالي'),
    h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: () => { st.f = { supplier: '', employee: '', from: '', to: '', type: '', sortKey: 'ts', sortDir: -1 }; supSel.value = ''; empSel.value = ''; fromI.value = ''; toI.value = ''; typeSel.value = ''; draw(); } }, 'الكل من البداية')));
  const supSel = h('select', {}, h('option', { value: '' }, 'الكل'), state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: st.f.supplier === s.id }, s.name)));
  supSel.addEventListener('change', () => { st.f.supplier = supSel.value; draw(); });
  const empSel = h('select', {}, h('option', { value: '' }, 'الكل'), state.accounts.filter(a => !a.deleted).map(a => h('option', { value: a.id, selected: st.f.employee === a.id }, a.name)));
  empSel.addEventListener('change', () => { st.f.employee = empSel.value; draw(); });
  const fromI = h('input', { type: 'date', value: st.f.from }), toI = h('input', { type: 'date', value: st.f.to });
  fromI.addEventListener('change', () => { st.f.from = fromI.value; draw(); });
  toI.addEventListener('change', () => { st.f.to = toI.value; draw(); });
  const typeSel = h('select', {}, h('option', { value: '' }, 'الكل'), h('option', { value: 'purchase' }, 'شراء'), h('option', { value: 'return' }, 'استرجاع شراء'));
  typeSel.value = st.f.type;
  typeSel.addEventListener('change', () => { st.f.type = typeSel.value; draw(); });
  page.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'المذخر'), supSel),
    h('div', { class: 'f-group' }, h('label', {}, 'الموظف'), empSel),
    h('div', { class: 'f-group' }, h('label', {}, 'من'), fromI, h('label', {}, 'إلى'), toI),
    h('div', { class: 'f-group' }, h('label', {}, 'نوع العملية'), typeSel)));
  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });
  page.append(bodyBox, footBox);
  const COLS = [['type','نوع العملية'],['employeeName','الموظف'],['supplierName','المذخر'],['date','التاريخ'],['time','الوقت'],['total','مبلغ القائمة'],['pay','نوع الدفع'],['debtAfter','الدين المتراكم'],[null,'تعديل']];
  function filtered() {
    return state.purchases.filter(p => !p.deleted &&
      (!st.f.supplier || p.supplierId === st.f.supplier) && (!st.f.employee || p.employeeId === st.f.employee) &&
      (!st.f.from || p.date >= st.f.from) && (!st.f.to || p.date <= st.f.to) && (!st.f.type || p.type === st.f.type)
    ).sort((a, b) => {
      const k = st.f.sortKey; const va = a[k], vb = b[k];
      if (typeof va === 'string' || typeof vb === 'string')
        return String(va || '').localeCompare(String(vb || ''), 'ar') * st.f.sortDir;
      return ((va || 0) - (vb || 0)) * st.f.sortDir;
    });
  }
  function draw() {
    const rows = filtered();
    bodyBox.innerHTML = '';
    const thead = h('tr', {}, COLS.map(([k, label]) =>
      h('th', { class: k ? 'sortable' : '', onclick: k ? () => { if (st.f.sortKey === k) st.f.sortDir *= -1; else { st.f.sortKey = k; st.f.sortDir = -1; } draw(); } : null },
        label, st.f.sortKey === k ? h('span', { class: 'sort-arw' }, st.f.sortDir === -1 ? ' ▼' : ' ▲') : null)));
    const tbody = h('tbody');
    rows.forEach(p => tbody.append(h('tr', {},
      h('td', {}, h('span', { class: 'badge ' + (p.type === 'purchase' ? 'b' : 'r') }, p.type === 'purchase' ? 'شراء' : 'استرجاع'),
        p.version > 1 ? h('span', { class: 'badge n' }, `ع${p.version}`) : null),
      h('td', {}, p.employeeName), h('td', {}, p.supplierName),
      h('td', { class: 'mono' }, fmtDate(p.ts)), h('td', { class: 'mono' }, fmtTime(p.ts)),
      h('td', { class: 'td-num td-total' }, fmt(p.total)),
      h('td', {}, h('span', { class: 'badge ' + (p.pay === 'cash' ? 'g' : 'r') }, p.pay === 'cash' ? 'كاش' : 'آجل')),
      h('td', { class: 'td-num', style: { color: 'var(--red)', fontWeight: 900 } }, p.pay === 'credit' ? fmt(p.debtAfter) : '—'),
      h('td', {}, h('button', { class: 'icon-btn edit', html: icon('edit'), onclick: () => openTab('editpurch', { purchaseId: p.id }) })),
    )));
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' }, h('thead', {}, thead), tbody)));
    if (!rows.length) bodyBox.append(h('div', { class: 'empty-note' }, 'لا نتائج ضمن الفلاتر المحددة'));
    /* الإجماليات */
    const tBuy = rows.filter(r => r.type === 'purchase').reduce((x, r) => x + r.total, 0) - rows.filter(r => r.type === 'return').reduce((x, r) => x + r.total, 0);
    let sellVal = 0, costVal = 0;
    rows.forEach(r => r.items.forEach(it => {
      const p = findProd(it.productId);
      const sign = r.type === 'purchase' ? 1 : -1;
      costVal += sign * it.total;
      if (p) sellVal += sign * salePerUnit(p, it.unitIdx) * it.qty;
    }));
    footBox.innerHTML = '';
    footBox.append(
      h('div', { class: 'sum-card b' }, h('label', {}, 'مبلغ المشتريات الكلي'), h('b', {}, animSpan(tBuy))),
      h('div', { class: 'sum-card n' }, h('label', {}, 'قيمة بيع أصناف هذه القوائم'), h('b', {}, animSpan(sellVal))),
      h('div', { class: 'sum-card big' }, h('label', {}, 'الربح المتوقع من هذه المشتريات'), h('b', {}, animSpan(sellVal - costVal, ' ' + cur()))));
  }
  draw();
  tab.el.append(page);
}

/* ───────────────────────── 19) تعديل قائمة شراء ───────────────────────── */
function renderEditPurchase(tab) {
  const pu = state.purchases.find(p => p.id === tab.props.purchaseId);
  if (!pu) { tab.el.append(h('div', { class: 'empty-note' }, 'القائمة غير موجودة')); return; }
  const readonly = tab.props.readonly;
  const st = tab.state;
  st.viewVer = st.viewVer || pu.version;
  const isLatest = !readonly && st.viewVer === pu.version;
  const snap = isLatest || readonly && st.viewVer === pu.version ? pu : pu.versions[st.viewVer - 1];
  if (!st.editItems || st.savedFor !== pu.version) { st.editItems = JSON.parse(JSON.stringify(snap.items)); st.discount = snap.discount; st.pay = snap.pay; st.savedFor = null; }
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon(readonly ? 'eye' : 'edit') }), `${readonly ? 'عرض' : 'تعديل'} قائمة شراء رقم ${pu.listNum} — ${pu.supplierName}`),
    h('div', { class: 'spacer' }),
    h('div', { class: 'ver-pills' }, h('span', { class: 'ver-note' }, 'النسخة:'),
      ...Array.from({ length: pu.version }, (_, i) => i + 1).map(v =>
        h('button', { class: 'ver-pill' + (v === st.viewVer ? ' cur' : ''), onclick: () => { st.viewVer = v; st.savedFor = null; renderTabContent(tab); } }, v)))));
  if (!isLatest && !readonly)
    page.append(h('div', { class: 'readonly-banner' }, h('span', { html: icon('lock') }), `نسخة رقم ${st.viewVer} — قراءة فقط. التعديل على آخر نسخة فقط.`));
  const tbody = h('tbody');
  function drawItems() {
    tbody.innerHTML = '';
    st.editItems.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1), h('td', { class: 'td-name' }, it.name),
        h('td', {}, it.unitName || (p ? p.units[it.unitIdx].name : '')),
        h('td', {}, isLatest ? (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 1, style: { width: '70px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          q.addEventListener('change', () => { it.qty = Math.max(1, num(q.value) || 1); drawT(); });
          return q;
        })() : fmt(it.qty)),
        h('td', {}, isLatest ? (() => {
          const pr = h('input', { type: 'number', value: it.buyPrice, min: 0, style: { width: '90px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          pr.addEventListener('change', () => { it.buyPrice = num(pr.value); drawT(); });
          return pr;
        })() : fmt(it.buyPrice)),
        h('td', { class: 'td-num td-total' }, fmt(it.buyPrice * it.qty)),
        isLatest ? h('td', {}, h('button', { class: 'icon-btn del', html: icon('trash'), onclick: () => { st.editItems.splice(i, 1); drawItems(); drawT(); } })) : h('td', {}, ''),
      ));
    });
  }
  const netEl = h('b', {}, '0');
  function drawT() { netEl.textContent = `${fmt(Math.max(0, st.editItems.reduce((s, it) => s + it.buyPrice * it.qty, 0) - st.discount))} ${cur()}`; }
  const discInp = h('input', { type: 'number', value: st.discount, min: 0, disabled: !isLatest, style: { width: '100px', border: '1.5px solid var(--line)', borderRadius: '10px', padding: '7px', fontWeight: 900, textAlign: 'center' } });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); drawT(); });
  const paySel = h('select', { class: 'unit-select', disabled: !isLatest },
    h('option', { value: 'cash', selected: st.pay === 'cash' }, 'كاش'), h('option', { value: 'credit', selected: st.pay === 'credit' }, 'آجل'));
  paySel.addEventListener('change', () => st.pay = paySel.value);
  page.append(h('div', { class: 'cart-wrap', style: { flex: 'none', maxHeight: '52vh' } },
    h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'سعر الشراء'), h('th', {}, 'المجموع'), h('th', {}, ''))), tbody))),
    h('div', { class: 'filter-bar' },
      h('div', { class: 'f-group' }, h('label', {}, 'الخصم'), discInp),
      h('div', { class: 'f-group' }, h('label', {}, 'نوع الدفع'), paySel),
      h('div', { class: 'spacer' }),
      h('div', { class: 'f-group' }, h('label', {}, 'الصافي'), netEl)));
  if (isLatest) {
    page.append(h('div', { style: { display: 'flex', gap: '10px' } },
      h('button', { class: 'btn g big', onclick: saveEdit }, h('span', { html: icon('check') }), 'حفظ التعديل (نسخة جديدة)'),
      pu.type === 'purchase' ? h('button', { class: 'btn r', onclick: makeReturn }, h('span', { html: icon('refresh') }), 'استرجاع للمذخر') : null));
  }
  tab.el.append(page);
  drawItems(); drawT();
  async function saveEdit() {
    if (!st.editItems.length) return toast('لا يمكن حفظ قائمة فارغة', 'r');
    pu.versions.push({ items: JSON.parse(JSON.stringify(pu.items)), total: pu.total, discount: pu.discount, pay: pu.pay });
    for (const it of pu.items) { const p = findProd(it.productId); if (p) p.stockBase = (p.stockBase || 0) - it.qtyBase; } // إرجاع أثر القديم
    const items = st.editItems.map(it => {
      const p = findProd(it.productId);
      return { ...it, qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.buyPrice * it.qty };
    });
    for (const it of items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) + it.qtyBase; await save('products', p); } }
    pu.items = items;
    pu.discount = st.discount;
    pu.total = Math.max(0, items.reduce((s, it) => s + it.total, 0) - st.discount);
    pu.pay = st.pay;
    pu.version += 1;
    pu.editedBy = me().name; pu.editedAt = Date.now();
    await save('purchases', pu);
    await recomputeSupplierDebt(pu.supplierId);
    st.savedFor = pu.version;
    toast(`حُفظت النسخة ${pu.version} وأُعيد حساب الدين المتراكم`);
    closeTab(tab.id);
  }
  async function makeReturn() {
    const yes = await confirmBox('سيتم إنشاء استرجاع شراء (إنقاص المخزون وتعديل دين المذخر). متابعة؟', { danger: true, okLabel: 'استرجاع', icon: 'refresh' });
    if (!yes) return;
    const ts = Date.now(); const acc = me();
    const ret = { id: uid(), type: 'return', version: 1, versions: [], originalId: pu.id,
      supplierId: pu.supplierId, supplierName: pu.supplierName, listNum: pu.listNum,
      items: JSON.parse(JSON.stringify(pu.items)), discount: pu.discount, total: pu.total, pay: pu.pay,
      employeeId: acc.id, employeeName: acc.name, ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID };
    await save('purchases', ret);
    for (const it of pu.items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) - it.qtyBase; await save('products', p); } }
    await recomputeSupplierDebt(pu.supplierId);
    toast('تم إنشاء استرجاع الشراء', 'b');
    closeTab(tab.id);
  }
}
/* إعادة حساب الدين المتراكم لمذخر — تطابق حسابي كامل بعد أي تعديل */
async function recomputeSupplierDebt(supplierId) {
  const sup = findSup(supplierId);
  if (!sup) return;
  const events = [
    ...state.purchases.filter(p => p.supplierId === supplierId && !p.deleted).map(p => ({ ts: p.ts, kind: 'p', doc: p })),
    ...state.payments.filter(p => p.supplierId === supplierId && !p.deleted).map(p => ({ ts: p.ts, kind: 'pay', doc: p })),
  ].sort((a, b) => a.ts - b.ts);
    let debt = sup.openingDebt || 0; // يبدأ التراكم من الرصيد الافتتاحي
  for (const ev of events) {
    if (ev.kind === 'p') {
      if (ev.doc.pay === 'credit') debt += ev.doc.type === 'purchase' ? ev.doc.total : -ev.doc.total;
      ev.doc.debtAfter = debt;
      await save('purchases', ev.doc);
    } else {
      debt -= ev.doc.amount + (ev.doc.kind === 'payment' ? (ev.doc.discount || 0) : 0); // التسديد والإيداع كلاهما يُنقص الدين
      ev.doc.debtAfter = debt;
      await save('payments', ev.doc);
    }
  }
  sup.debt = debt;
  const ps = state.purchases.filter(p => p.supplierId === supplierId && p.type === 'purchase' && !p.deleted).sort((a, b) => b.ts - a.ts);
  sup.lastPurchase = ps[0] ? { amount: ps[0].total, ts: ps[0].ts } : null;
  const pays = state.payments.filter(p => p.supplierId === supplierId && p.kind === 'payment' && !p.deleted).sort((a, b) => b.ts - a.ts);
  sup.lastPayment = pays[0] ? { amount: pays[0].amount, ts: pays[0].ts } : null;
  await save('suppliers', sup);
}

/* ───────────────────────── 20) المخزن ───────────────────────── */
function renderInventory(tab) {
  const st = tab.state;
  st.f = st.f || { q: '', sortKey: 'createdAt', sortDir: -1 };
  const page = h('div', { class: 'page det-page' });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('store') }), 'المخزن'),
    h('div', { class: 'spacer' }),
    h('button', { class: 'btn g', onclick: () => openTab('product') }, h('span', { html: icon('plus') }), 'إضافة صنف')));
  const qInp = h('input', { type: 'text', placeholder: 'بحث سريع بالاسم أو الباركود…', value: st.f.q });
  qInp.addEventListener('input', () => { st.f.q = qInp.value; draw(); });
  page.append(h('div', { class: 'filter-bar' }, h('div', { class: 'f-group', style: { flex: 1 } }, h('span', { html: icon('search') }), qInp)));
  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });
  page.append(bodyBox, footBox);
  const COLS = [[null,'ت'],['brandName','اسم المنتج'],[null,'سعر الشراء'],[null,'سعر البيع'],[null,'ربح القطعة'],['stockBase','العدد (وحدة صغرى)'],['expiry','الإكسباير'],[null,'إجراء']];
  function draw() {
    let rows = state.products.filter(p => !p.deleted);
    if (st.f.q.trim()) rows = rows.filter(p => prodMatches(p, st.f.q));
    rows.sort((a, b) => {
      const k = st.f.sortKey;
      if (k === 'brandName') return a.brandName.localeCompare(b.brandName, 'ar') * st.f.sortDir;
      return ((a[k] || 0) - (b[k] || 0)) * st.f.sortDir;
    });
    bodyBox.innerHTML = '';
    const tbody = h('tbody');
    rows.forEach((p, i) => {
      const cBase = p.purchasePriceTop / (baseFactor(p) || 1);
      const expired = p.expiry && p.expiry < dateStr().slice(0, 7);
      const nearExp = !expired && p.expiry && p.expiry <= dateStr(Date.now() + 90 * 864e5).slice(0, 7);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, p.brandName,coTag(p), h('small', {}, `${p.scientificName || ''} ${p.form || ''} ${p.dose || ''}`.trim())),
        h('td', { class: 'td-num td-cost' }, fmt(cBase)),
        h('td', { class: 'td-num td-sale' }, fmt(p.salePriceBase)),
        h('td', { class: 'td-num', style: { color: 'var(--green)' } }, fmt(p.salePriceBase - cBase)),
        h('td', {}, h('span', { class: 'badge ' + ((p.stockBase || 0) <= 0 ? 'r' : (p.stockBase || 0) <= (state.settings.lowStock ?? 10) ? 'amber' : 'g') },
          `${fmt(p.stockBase || 0)} ${smallUnitName(p)}`)),
        h('td', {}, p.expiry ? h('span', { class: 'badge ' + (expired ? 'r' : nearExp ? 'amber' : 'n') }, p.expiry) : '—'),
        h('td', {}, productActions(p, tab)),
      ));
    });
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, COLS.map(([k, label]) =>
        h('th', { class: k ? 'sortable' : '', onclick: k ? () => { if (st.f.sortKey === k) st.f.sortDir *= -1; else { st.f.sortKey = k; st.f.sortDir = 1; } draw(); } : null },
          label, st.f.sortKey === k ? h('span', { class: 'sort-arw' }, st.f.sortDir === -1 ? ' ▼' : ' ▲') : null)))),
      tbody)));
    if (!rows.length) bodyBox.append(h('div', { class: 'empty-note' }, 'المخزن فارغ — أضف الأصناف من قائمة الشراء'));
    let tCost = 0, tSale = 0;
    state.products.filter(p => !p.deleted).forEach(p => {
      const cBase = p.purchasePriceTop / (baseFactor(p) || 1);
      tCost += cBase * (p.stockBase || 0);
      tSale += p.salePriceBase * (p.stockBase || 0);
    });
    footBox.innerHTML = '';
    footBox.append(
      h('div', { class: 'sum-card b' }, h('label', {}, 'مجموع شراء المخزن'), h('b', {}, `${fmt(tCost)} ${cur()}`)),
      h('div', { class: 'sum-card n' }, h('label', {}, 'مجموع بيع المخزن'), h('b', {}, `${fmt(tSale)} ${cur()}`)),
      h('div', { class: 'sum-card big' }, h('label', {}, 'الربح المتوقع'), h('b', {}, `${fmt(tSale - tCost)} ${cur()}`)));
  }
  draw();
  tab.el.append(page);
}

/* ───────────────────────── 20-ب) مخزن مفاتيح الذكاء الاصطناعي: عدد غير محدود، يُرفع للسحابة، ويدور تلقائياً ───────────────────────── */
const KeyPool = (() => {
  let list = [], loaded = null, polling = false, listening = false, cssDone = false;
  const subs = new Set();
  const S = x => String(x == null ? '' : x).trim();
  const cloudReady = () => typeof Sync !== 'undefined' && Sync.ready && Sync.db;
  const notify = () => subs.forEach(f => { try { f(); } catch (_) {} });
  const persistLocal = () => DB.put('meta', { id: 'aikeys', list: JSON.parse(JSON.stringify(list)) }).catch(() => {});
  const norm = k => ({
    id: S(k.id), key: S(k.key), label: S(k.label), addedAt: +k.addedAt || 0, disabled: !!k.disabled, bad: S(k.bad), used: +k.used || 0,
    ex: { pro: +(k.ex && k.ex.pro) || 0, flash: +(k.ex && k.ex.flash) || 0 },
    exAt: { pro: +(k.exAt && k.exAt.pro) || 0, flash: +(k.exAt && k.exAt.flash) || 0 },
  });
  const pushCloud = k => {
    if (!cloudReady()) return;
    try { Sync.db.ref('pos/aiKeys/' + k.id).set(JSON.parse(JSON.stringify(k))).catch(e => console.warn('aiKeys cloud:', e)); } catch (_) {}
  };
  const upsert = k => {
    const n = norm(k || {});
    if (!n.id || !n.key) return;
    const i = list.findIndex(x => x.id === n.id);
    if (i >= 0) list[i] = n; else list.push(n);
  };

  /* الاستماع للسحابة: أي مفتاح يُضاف أو تتغير حالته على أي جهاز يصل لكل الأجهزة */
  function listen() {
    if (listening || polling) return;
    polling = true;
    const t = setInterval(() => {
      if (!cloudReady()) return;
      clearInterval(t); polling = false; listening = true;
      const ref = Sync.db.ref('pos/aiKeys');
      const apply = snap => { const v = snap.val(); if (v && v.id) { upsert(v); persistLocal(); notify(); } };
      ref.on('child_added', apply, e => console.warn('aiKeys:', e));
      ref.on('child_changed', apply, e => console.warn('aiKeys:', e));
      ref.on('child_removed', snap => { const id = snap.key; list = list.filter(x => x.id !== id); persistLocal(); notify(); }, e => console.warn('aiKeys:', e));
      ref.once('value').then(s => { const c = s.val() || {}; list.forEach(k => { if (!c[k.id]) pushCloud(k); }); }).catch(() => {});
    }, 1500);
  }
  function load() {
    if (!loaded) loaded = (async () => {
      try { const m = await DB.get('meta', 'aikeys'); if (m && Array.isArray(m.list)) m.list.forEach(upsert); } catch (_) {}
      notify();
    })();
    listen();
    return loaded;
  }

  /* الأولوية: مفتاح استُهلك سابقاً وعاد متاحاً (الأقدم استهلاكاً أولاً)، ثم المفاتيح التي لم تُستهلك بترتيب إضافتها */
  function next(tried, tier) {
    const now = Date.now();
    const av = list.filter(k => !k.disabled && !k.bad && !tried.has(k.id) && k.ex[tier] <= now);
    const back = av.filter(k => k.exAt[tier] > 0).sort((a, b) => a.exAt[tier] - b.exAt[tier]);
    const fresh = av.filter(k => !(k.exAt[tier] > 0)).sort((a, b) => a.addedAt - b.addedAt);
    return back[0] || fresh[0] || null;
  }
  const mark = (id, fn) => { const k = list.find(x => x.id === id); if (!k) return; fn(k); persistLocal(); pushCloud(k); notify(); };
  const exhaust = (id, tier, until) => mark(id, k => { k.ex[tier] = until; k.exAt[tier] = Date.now(); });
  const markBad = (id, why) => mark(id, k => { k.bad = S(why).slice(0, 80) || 'مرفوض'; });
  const touch = id => mark(id, k => { k.used = (k.used || 0) + 1; });
  const resetState = id => mark(id, k => { k.bad = ''; k.ex = { pro: 0, flash: 0 }; });
  const toggle = id => mark(id, k => { k.disabled = !k.disabled; if (!k.disabled) k.bad = ''; });
  const soonest = tier => {
    const now = Date.now();
    const t = list.filter(k => !k.disabled && !k.bad && k.ex[tier] > now).map(k => k.ex[tier]);
    return t.length ? Math.min(...t) : 0;
  };
  async function remove(id) {
    list = list.filter(x => x.id !== id);
    persistLocal(); notify();
    if (cloudReady()) { try { await Sync.db.ref('pos/aiKeys/' + id).remove(); } catch (e) { console.warn('aiKeys remove:', e); } }
  }
  async function addMany(text, label) {
    await load();
    const keys = String(text || '').split(/[\s,;]+/).map(S).filter(Boolean);
    let added = 0, dup = 0, bad = 0;
    for (const key of keys) {
      if (!/^[A-Za-z0-9_\-]{20,}$/.test(key)) { bad++; continue; }
      if (list.some(x => x.key === key)) { dup++; continue; }
      const k = norm({ id: uid(), key, label: keys.length === 1 ? label : '', addedAt: Date.now() + added });
      list.push(k); pushCloud(k); added++;
    }
    persistLocal(); notify();
    return { added, dup, bad };
  }

  function css() {
    if (cssDone) return; cssDone = true;
    const st = document.createElement('style'); st.id = 'kp-css';
    st.textContent = `
.kp-wrap{display:flex;flex-direction:column;gap:12px}
.kp-ta,.kp-in{width:100%;border:1.5px solid var(--line);border-radius:12px;padding:10px 13px;font-weight:700;outline:none;font-family:inherit}
.kp-ta{direction:ltr;resize:vertical}
.kp-list{display:flex;flex-direction:column;gap:8px;max-height:46vh;overflow:auto}
.kp-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;border:1px solid var(--line);border-radius:14px;padding:9px 12px}
.kp-row.cur{border-color:#14b8a6;box-shadow:0 0 0 3px rgba(20,184,166,.16)}
.kp-name{font-weight:900}
.kp-mask{direction:ltr;font-family:monospace;color:var(--muted);font-weight:700}
.kp-chip{display:inline-block;padding:0 10px;border-radius:999px;font-size:12px;font-weight:900;line-height:1.9}
.kp-chip.ok{background:#d9f7e6;color:#047857}.kp-chip.warn{background:#fff0c9;color:#a16207}.kp-chip.bad{background:#ffdcdc;color:#b91c1c}.kp-chip.na{background:#e6ecec;color:#52615f}.kp-chip.cur{background:#14b8a6;color:#fff}
.kp-sp{flex:1}
.kp-info{font-weight:800;font-size:13px;color:var(--muted);line-height:1.9}
`;
    document.head.append(st);
  }

  function openManager() {
    css();
    const ta = h('textarea', { class: 'kp-ta', rows: 3, dir: 'ltr', placeholder: 'AIza…  الصق مفتاحاً أو عدة مفاتيح (كل مفتاح في سطر)' });
    const lbl = h('input', { class: 'kp-in', placeholder: 'اسم اختياري للمفتاح (يُستعمل عند إضافة مفتاح واحد)' });
    const info = h('div', { class: 'kp-info' });
    const box = h('div', { class: 'kp-list' });
    const draw = () => {
      box.innerHTML = '';
      const now = Date.now();
      const cur = next(new Set(), 'pro');
      const rows = [...list].sort((a, b) => a.addedAt - b.addedAt);
      const ready = rows.filter(k => !k.disabled && !k.bad && k.ex.pro <= now).length;
      info.textContent = `${rows.length} مفتاح — جاهز الآن للموديل الأذكى: ${ready}. المفاتيح محفوظة في السحابة وتصل لكل الأجهزة، ويُستخدم أول مفتاح جاهز وعند استهلاكه يُنتقل للتالي تلقائياً، وأي مفتاح يعود متاحاً تكون له الأولوية.`;
      if (!rows.length) { box.append(h('div', { class: 'empty-note' }, 'لا توجد مفاتيح بعد — الصق مفاتيحك بالأعلى')); return; }
      rows.forEach((k, i) => {
        let chip;
        if (k.bad) chip = h('span', { class: 'kp-chip bad' }, 'مرفوض: ' + k.bad);
        else if (k.disabled) chip = h('span', { class: 'kp-chip na' }, 'معطّل');
        else if (k.ex.pro > now) chip = h('span', { class: 'kp-chip warn' }, `مستهلك حتى ${fmtDate(k.ex.pro)} ${fmtTime(k.ex.pro)}`);
        else chip = h('span', { class: 'kp-chip ok' }, k.exAt.pro > 0 ? 'عاد متاحاً — له الأولوية' : 'جاهز');
        box.append(h('div', { class: 'kp-row' + (cur && cur.id === k.id ? ' cur' : '') },
          h('span', { class: 'kp-name' }, k.label || `مفتاح ${i + 1}`),
          h('span', { class: 'kp-mask' }, k.key.slice(0, 6) + '…' + k.key.slice(-4)),
          chip,
          cur && cur.id === k.id ? h('span', { class: 'kp-chip cur' }, 'يُستخدم الآن') : null,
          h('span', { class: 'kp-chip na' }, `استُخدم ${k.used} مرة`),
          h('span', { class: 'kp-sp' }),
          (k.bad || k.ex.pro > now || k.ex.flash > now) ? h('button', { class: 'mini-btn blue', onclick: () => resetState(k.id) }, 'تصفير الحالة') : null,
          h('button', { class: 'mini-btn blue', onclick: () => toggle(k.id) }, k.disabled ? 'تفعيل' : 'تعطيل'),
          h('button', { class: 'mini-btn red', onclick: async () => {
            if (await confirmBox('حذف هذا المفتاح نهائياً من كل الأجهزة؟', { danger: true, okLabel: 'حذف' })) { await remove(k.id); toast('حُذف المفتاح', 'b'); }
          } }, 'حذف')));
      });
    };
    const addBtn = h('button', { class: 'btn g', onclick: async () => {
      if (!ta.value.trim()) return toast('الصق المفتاح أولاً', 'r');
      const r = await addMany(ta.value, lbl.value);
      if (!r.added && !r.dup) return toast('لم يُقبل أي مفتاح — تأكد من نسخه كاملاً', 'r');
      ta.value = ''; lbl.value = '';
      toast(`أُضيف ${r.added} مفتاح` + (r.dup ? ` — ${r.dup} مكرر` : '') + (r.bad ? ` — ${r.bad} غير صالح` : ''), r.added ? 'g' : 'r');
    } }, h('span', { html: icon('plus') }), 'إضافة وحفظ في السحابة');
    const body = h('div', { class: 'kp-wrap' }, ta, lbl, h('div', {}, addBtn), info, box);
    openModal({ title: 'مفاتيح الموسوعة الدوائية', icon: 'lock', body, wide: true, onClose: () => subs.delete(draw) });
    subs.add(draw);
    load().then(draw);
    draw();
  }

  return { load, next, exhaust, markBad, touch, soonest, openManager, count: () => list.length };
})();

/* ───────────────────────── 20-أ) الموسوعة الدوائية الذكية: Gemini + بحث ويب موثّق + ذاكرة محلية وسحابية ───────────────────────── */
const DrugInfo = (() => {
  const A = x => Array.isArray(x) ? x : (x && typeof x === 'object' ? Object.values(x) : (x ? [x] : []));
  const S = x => String(x == null ? '' : x).trim();
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const inflight = new Map();
  let uidN = 0, cssDone = false;

  /* الاسم العلمي → مكوّناته (تركيبة إن وُجد + أو / أو &) ثم مفتاح تخزين موحّد مرتّب أبجدياً */
  const splitParts = sci => S(sci)
    .replace(/\(.*?\)/g, ' ')
    .split(/\s*(?:\+|\/|&|,|;|\band\b)\s*/i)
    .map(x => x.replace(/\d+(?:[.,]\d+)?\s*(?:mg|mcg|µg|ug|gm|g|ml|iu|%|units?)(?![a-z])/ig, ' ').replace(/\s+/g, ' ').trim())
    .filter(Boolean);
  const keyOf = ps => ps.map(x => x.toLowerCase().replace(/[^a-z0-9\u0600-\u06FF]+/g, '_').replace(/^_+|_+$/g, '')).filter(Boolean).sort().join('__').slice(0, 200);

  /* ── اختيار أذكى موديل متاح للمفتاح: Pro أولاً ثم Flash احتياطاً ── */
  let mCache = { k: '', list: null, ts: 0 };
  async function listModels(apiKey) {
    if (mCache.list && mCache.k === apiKey && Date.now() - mCache.ts < 600000) return mCache.list;
    try {
      const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000', { headers: { 'x-goog-api-key': apiKey } });
      if (!r.ok) return null;
      const d = await r.json();
      const names = (d.models || []).filter(m => (m.supportedGenerationMethods || []).includes('generateContent')).map(m => String(m.name || '').replace(/^models\//, ''));
      mCache = { k: apiKey, list: names, ts: Date.now() };
      return names;
    } catch (_) { return null; }
  }
  function order(avail) {
    const FALL = ['gemini-pro-latest', 'gemini-2.5-pro', 'gemini-flash-latest', 'gemini-2.5-flash'];
    if (!avail || !avail.length) return FALL;
    const bad = /(tts|image|live|audio|robotics|computer|embedding|learnlm|vision|gemma|nano|lite|customtools|exp)/;
    const ver = n => { const m = /gemini-(\d+(?:\.\d+)?)/.exec(n); return m ? parseFloat(m[1]) : 0; };
    const pros = avail.filter(n => /^gemini-.*pro/.test(n) && !bad.test(n))
      .sort((a, b) => ((b === 'gemini-pro-latest') - (a === 'gemini-pro-latest')) || (ver(b) - ver(a)) || (/preview/.test(a) - /preview/.test(b)));
    const flash = ['gemini-flash-latest', 'gemini-2.5-flash'].filter(n => avail.includes(n));
    const out = [...pros.slice(0, 4), ...flash];
    return out.length ? out : FALL;
  }

  function buildPrompt(p, ps) {
    const clean = v => S(v).replace(/["\r\n]+/g, ' ');
    const combo = ps.length > 1;
    return `You are a senior clinical pharmacist and drug-information specialist. Use Google Search to verify EVERY fact against authoritative sources only (FDA/DailyMed labels, EMA SmPC, MHRA/BNF, WHO, NHS, MedlinePlus, Mayo Clinic, Drugs.com professional monographs, LactMed, NICE). Never guess. If a fact cannot be verified, write "غير مؤكد" for that field instead of inventing it.

Drug (scientific name as entered by the pharmacy): "${clean(p.scientificName)}"
${combo ? 'This is a FIXED-DOSE COMBINATION of: ' + ps.join(' + ') + '. Describe the combination product as a whole (uses, dosing of the combination, safety of the combination). In "moa.steps" give one item per component. Mention component-specific warnings where they differ.' : 'This is a single active ingredient.'}
Local product for context only: trade name "${clean(p.brandName)}", form "${clean(p.form)}", strength "${clean(p.dose)}".

Write ALL text values in clear Arabic for a pharmacist. Keep drug names, doses, units and brand names in English (Latin) letters.
Strict brevity so everything fits on one screen: every string at most 200 characters; every array at most 6 items.
Rules:
- "brands": up to 8 brand names of this exact generic (or this exact combination) that are genuinely marketed in Iraq or commonly written in Iraqi prescriptions. "n" = brand name in English, "c" = manufacturer. Include only brands you are certain exist, otherwise return an empty array.
- "doses": one object per commercially available strength/form, with: f = form and strength, who = patient group (adult / child with age or weight), d = dose and frequency, how = route and timing (with or without food, etc.), tip = key counseling advice for the patient or "".
- "safe": for each of preg, lact, child, htn, dm, kid, liv, heart: s = one of "safe","caution","unsafe","unknown"; t = short reason with trimester or dose adjustment where relevant. For child also set "age" = minimum allowed age/weight (for example "≥ 12 سنة") or "غير مؤكد".
- "adv.contra": absolute contraindications (cases where the pharmacist must NOT dispense).
- Do not put markdown, citations, links or footnote marks inside any string.
Return ONLY one JSON object, starting with { and ending with }, in exactly this shape:
{"brands":[{"n":"","c":""}],"uses":{"sum":"","list":[""]},"doses":[{"f":"","who":"","d":"","how":"","tip":""}],"moa":{"sum":"","steps":[""]},"adv":{"common":[""],"serious":[""],"contra":[""]},"safe":{"preg":{"s":"","t":""},"lact":{"s":"","t":""},"child":{"s":"","age":"","t":""},"htn":{"s":"","t":""},"dm":{"s":"","t":""},"kid":{"s":"","t":""},"liv":{"s":"","t":""},"heart":{"s":"","t":""}},"extra":{"cls":"","onset":"","half":"","inter":[""],"tips":[""],"store":""}}`;
  }

  function parseJson(text) {
    const t = String(text || '').replace(/```json|```/g, '').trim();
    const s = t.indexOf('{'), e = t.lastIndexOf('}');
    if (s < 0 || e < 0) return null;
    try { return JSON.parse(t.slice(s, e + 1)); } catch (_) { return null; }
  }

  async function callModel(model, key, prompt, grounded) {
    const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), 180000);
    try {
      const body = { contents: [{ role: 'user', parts: [{ text: prompt }] }], generationConfig: { temperature: 0.1, maxOutputTokens: 32000 } };
      if (grounded) body.tools = [{ google_search: {} }];
      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key }, body: JSON.stringify(body), signal: ctl.signal,
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        const msg = S(e && e.error && e.error.message).slice(0, 160);
        let raw = ''; try { raw = JSON.stringify(e).slice(0, 3000); } catch (_) {}
        return { ok: false, status: res.status, msg, raw, fatal: res.status === 401 || res.status === 403 || (res.status === 400 && /api key/i.test(msg)) };
      }
      const data = await res.json();
      const c0 = data.candidates && data.candidates[0];
      const text = ((c0 && c0.content && c0.content.parts) || []).map(x => x.text || '').join('');
      const gm = (c0 && c0.groundingMetadata) || {};
      const sources = A(gm.groundingChunks).map(g => g && g.web ? { t: S(g.web.title), u: S(g.web.uri) } : null).filter(Boolean);
      if (!text.trim()) return { ok: false, status: 0, msg: (c0 && c0.finishReason) || 'ردّ فارغ' };
      return { ok: true, text, sources };
    } catch (e) {
      return { ok: false, status: 0, msg: e && e.name === 'AbortError' ? 'انتهت المهلة' : 'تعذّر الاتصال' };
    } finally { clearTimeout(to); }
  }

  /* التوليد: بحث ويب موثّق أولاً عبر كل الموديلات، ولا يُسمح بالتوليد بلا بحث إلا إذا رفضت الموديلات أداة البحث نفسها */
  /* منتصف ليل توقيت المحيط الهادئ = موعد تصفير الحصة اليومية لمفاتيح Gemini */
  function nextPTMidnight() {
    const now = Date.now();
    const parts = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Los_Angeles', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }).formatToParts(new Date(now));
    const g = t => +parts.find(x => x.type === t).value;
    const hh = g('hour') % 24;
    return now + (86400 - (hh * 3600 + g('minute') * 60 + g('second'))) * 1000 + 1000;
  }
  function quotaUntil(r) {
    const raw = (r.raw || '') + ' ' + (r.msg || '');
    if (/PerDay|per day|daily/i.test(raw)) return nextPTMidnight();
    const m = /"retryDelay"\s*:\s*"(\d+(?:\.\d+)?)s"/.exec(raw);
    return Date.now() + ((m ? Math.ceil(parseFloat(m[1])) + 2 : 65) * 1000);
  }

  /* التوليد: يبدأ بأذكى موديل عبر المفاتيح بالترتيب؛ عند استهلاك مفتاح ينتقل للتالي، ولا ينزل لموديل أخف إلا بعد استهلاك كل المفاتيح */
  async function generate(p, ps, key) {
    if (navigator.onLine === false) throw new Error('لا يوجد اتصال بالإنترنت — أول بحث عن أي دواء يحتاج الإنترنت');
    await KeyPool.load();
    if (!KeyPool.count()) throw new Error('لا توجد مفاتيح — أضفها من: الإعدادات ← الماسح الذكي ← مفاتيح الموسوعة الدوائية');
    const prompt = buildPrompt(p, ps);
    const errs = [];
    for (const tier of ['pro', 'flash']) {
      const tried = new Set();
      for (let ent = KeyPool.next(tried, tier); ent; ent = KeyPool.next(tried, tier)) {
        tried.add(ent.id);
        const models = order(await listModels(ent.key)).filter(n => tier === 'pro' ? /pro/.test(n) : !/pro/.test(n)).slice(0, tier === 'pro' ? 4 : 2);
        let hits = 0, until = 0, dead = false;
        for (const model of models) {
          let quota = false;
          for (let attempt = 0; attempt < 2; attempt++) {
            let r = await callModel(model, ent.key, prompt, true);
            if (!r.ok && r.status === 400 && /tool|search|ground/i.test(r.msg)) r = await callModel(model, ent.key, prompt, false);
            if (r.ok) {
              const obj = parseJson(r.text);
              if (obj && (obj.uses || obj.doses)) {
                KeyPool.touch(ent.id);
                return { key, sci: S(p.scientificName), parts: ps, data: obj, sources: r.sources, grounded: r.sources.length > 0, model, createdAt: Date.now(), v: 1 };
              }
              errs.push(`${model}: ردّ غير صالح`); break;
            }
            if (r.fatal && /api key|leaked|expired|invalid|disabled/i.test(r.msg + ' ' + (r.raw || ''))) { KeyPool.markBad(ent.id, r.msg); dead = true; break; }
            if (r.status === 429) { quota = true; const u = quotaUntil(r); until = until ? Math.min(until, u) : u; break; }
            errs.push(`${model} (${r.status || '—'}): ${r.msg || 'خطأ'}`);
            if ([500, 503].includes(r.status) && attempt === 0) { await sleep(3000); continue; }
            break;
          }
          if (dead) break;
          if (quota) hits++;
        }
        if (!dead && models.length && hits === models.length) KeyPool.exhaust(ent.id, tier, until);
      }
    }
    const soon = KeyPool.soonest('pro');
    throw new Error((soon ? 'كل المفاتيح مستهلكة حالياً — أقربها يتوفر ' + fmtDate(soon) + ' ' + fmtTime(soon) + '. ' : '') + (errs.join(' ║ ') || 'لا يوجد مفتاح جاهز — راجع المفاتيح'));
  }

  /* ── الذاكرة: محلية (IndexedDB) ثم سحابية (Firebase) — يُستدعى الذكاء الاصطناعي لأول بحث فقط ── */
  const cloudReady = () => typeof Sync !== 'undefined' && Sync.ready && Sync.db;
  async function lookup(key) {
    try {
      const loc = await DB.get('meta', 'drug:' + key);
      if (loc && loc.data) { if (loc.cloud === false) store(loc); return loc; }
    } catch (_) {}
    if (cloudReady()) {
      try {
        const snap = await Promise.race([Sync.db.ref('pos/drugInfo/' + key).once('value'), new Promise((_, rej) => setTimeout(() => rej(new Error('t')), 7000))]);
        const v = snap.val();
        if (v && v.data) {
          const rec = { ...v, id: 'drug:' + key, cloud: true };
          try { await DB.put('meta', rec); } catch (_) {}
          return rec;
        }
      } catch (_) {}
    }
    return null;
  }
  async function store(rec) {
    let ok = false;
    if (cloudReady()) {
      try {
        const doc = JSON.parse(JSON.stringify(rec)); delete doc.id; delete doc.cloud;
        await Promise.race([Sync.db.ref('pos/drugInfo/' + rec.key).set(doc), new Promise((_, rej) => setTimeout(() => rej(new Error('t')), 8000))]);
        ok = true;
      } catch (e) { console.warn('drugInfo cloud:', e); }
    }
    rec.cloud = ok;
    try { await DB.put('meta', { ...rec, id: 'drug:' + rec.key }); } catch (_) {}
  }

  /* ── الأيقونة المجسّمة ── */
  function capsule() {
    const n = ++uidN;
    return `<svg viewBox="0 0 64 64" aria-hidden="true"><defs>
      <linearGradient id="dc1-${n}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8af0ff"/><stop offset="1" stop-color="#1f7ae0"/></linearGradient>
      <linearGradient id="dc2-${n}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ff8a7a"/><stop offset="1" stop-color="#d4213d"/></linearGradient>
      <linearGradient id="dc3-${n}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fff2a8"/><stop offset="1" stop-color="#f5a60b"/></linearGradient>
      <linearGradient id="dc4-${n}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".85"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></linearGradient></defs>
      <ellipse cx="30" cy="57" rx="18" ry="3.2" fill="#0b2f2c" opacity=".22"/>
      <g transform="rotate(-38 30 31)">
        <rect x="6" y="20" width="48" height="22" rx="11" fill="url(#dc1-${n})"/>
        <path d="M30 20h13a11 11 0 0 1 0 22H30z" fill="url(#dc2-${n})"/>
        <rect x="10" y="23" width="40" height="6" rx="3" fill="url(#dc4-${n})"/>
        <rect x="6" y="20" width="48" height="22" rx="11" fill="none" stroke="#0b2f2c" stroke-opacity=".18"/>
      </g>
      <path d="M50 4l2.4 6.6 6.6 2.4-6.6 2.4L50 22l-2.4-6.6L41 13l6.6-2.4z" fill="url(#dc3-${n})" stroke="#c78400" stroke-width=".6"/>
    </svg>`;
  }

  function css() {
    if (cssDone) return; cssDone = true;
    const st = document.createElement('style'); st.id = 'di-css';
    st.textContent = `
.di-3d{width:46px;height:46px;border:0;border-radius:14px;padding:6px;cursor:pointer;display:grid;place-items:center;background:linear-gradient(145deg,#fff,#d9ebe8);box-shadow:0 5px 0 #aecbc7,0 12px 18px rgba(11,47,44,.28),inset 0 2px 0 #fff;transition:transform .18s ease,box-shadow .18s ease;animation:diFloat 3.2s ease-in-out infinite}
.di-3d svg{width:100%;height:100%;filter:drop-shadow(0 3px 3px rgba(0,0,0,.25))}
.di-3d:hover{transform:perspective(320px) rotateX(12deg) rotateY(-14deg) translateY(-3px);box-shadow:0 8px 0 #aecbc7,0 18px 24px rgba(11,47,44,.32),inset 0 2px 0 #fff;animation:none}
.di-3d:active{transform:translateY(4px);box-shadow:0 1px 0 #aecbc7,0 4px 8px rgba(11,47,44,.25),inset 0 2px 0 #fff}
.di-3d:focus-visible{outline:3px solid #14b8a6;outline-offset:3px}
@keyframes diFloat{0%,100%{translate:0 0}50%{translate:0 -3px}}
@keyframes diBlink{50%{opacity:0}}
@keyframes diSpin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.di-3d{animation:none}.di-spin{animation:none}}
.di-box{width:min(1340px,98vw)!important;max-width:none!important;height:93vh!important;max-height:93vh!important;display:flex!important;flex-direction:column}
.di-box .modal-body{flex:1;min-height:0;padding:0!important;overflow:hidden!important}
.di-root{height:100%;display:flex;flex-direction:column;background:#eaf3f1;color:#14302d;font-family:inherit;direction:rtl}
.di-top{flex:none;display:flex;gap:22px;align-items:center;padding:12px 20px;background:linear-gradient(120deg,#0b2f2c,#14544d);color:#effaf7}
.di-id{display:flex;gap:14px;align-items:center;flex:1.2;min-width:0}
.di-svg{width:62px;height:62px;flex:none;filter:drop-shadow(0 8px 8px rgba(0,0,0,.35));transform:perspective(300px) rotateY(-14deg) rotateX(6deg)}
.di-svg svg{width:100%;height:100%}
.di-lbl{font-size:11.5px;font-weight:800;color:#9fd8cf}
.di-trade{font-size:21px;font-weight:900;line-height:1.35;direction:ltr;text-align:right}
.di-trade small{font-size:12px;font-weight:700;color:#9fd8cf;margin-inline-start:8px}
.di-sci{font-size:14.5px;font-weight:800;direction:ltr;text-align:right;color:#d9fff7}
.di-sci .di-chip{margin-inline-start:8px;direction:rtl}
.di-brands{flex:1;min-width:0}
.di-bl{display:flex;flex-wrap:wrap;gap:6px;margin-top:5px}
.di-bchip{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.22);border-radius:10px;padding:3px 10px;font-size:12.5px;font-weight:800;direction:ltr}
.di-bchip small{font-weight:700;color:#9fd8cf;margin-inline-start:6px}
.di-grid{flex:1;min-height:0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));grid-template-rows:minmax(0,.86fr) minmax(0,1.14fr);gap:11px;padding:11px 14px}
.di-card{background:#fff;border-radius:16px;border:1px solid #d3e5e2;box-shadow:0 8px 22px rgba(11,47,44,.08);display:flex;flex-direction:column;min-height:0;overflow:hidden}
.di-card>header{flex:none;display:flex;align-items:center;gap:8px;padding:8px 13px;font-size:14px;color:#fff}
.di-card>header .ic{width:17px;height:17px}
.di-card.c1>header{background:linear-gradient(90deg,#0f766e,#14b8a6)}
.di-card.c2>header{background:linear-gradient(90deg,#1d4ed8,#3b82f6)}
.di-card.c3>header{background:linear-gradient(90deg,#6d28d9,#8b5cf6)}
.di-card.c4>header{background:linear-gradient(90deg,#b91c1c,#ef4444)}
.di-card.c5>header{background:linear-gradient(90deg,#047857,#10b981)}
.di-card.c6>header{background:linear-gradient(90deg,#b45309,#f59e0b)}
.di-cb{flex:1;min-height:0;overflow:auto;padding:9px 13px 11px;font-size:12.6px;line-height:1.72;font-weight:600;scrollbar-width:thin}
.di-p{margin-bottom:5px}
.di-li{position:relative;padding-inline-start:14px;margin-bottom:2px}
.di-li:before{content:"";position:absolute;inset-inline-start:2px;top:.72em;width:6px;height:6px;border-radius:50%;background:#14b8a6}
.di-lab{font-weight:900;font-size:12px;color:#0f766e;margin:6px 0 2px}
.di-lab.bad{color:#c0392b}
.di-dose{border:1px solid #dcebe8;border-radius:10px;padding:5px 9px;margin-bottom:6px;background:#f6fbfa}
.di-dh{font-weight:900;color:#1d4ed8;direction:ltr;text-align:right}
.di-tip{color:#0f766e}
.di-srow{display:flex;gap:8px;align-items:flex-start;padding:4px 0;border-bottom:1px dashed #dfebe8}
.di-srow>b{flex:none;width:74px;font-weight:900}
.di-srow>span{flex:1;min-width:0}
.di-chip{display:inline-block;flex:none;padding:0 9px;border-radius:999px;font-size:11.5px;font-weight:900;line-height:1.8}
.di-chip.ok{background:#d9f7e6;color:#047857}.di-chip.warn{background:#fff0c9;color:#a16207}.di-chip.bad{background:#ffdcdc;color:#b91c1c}.di-chip.na{background:#e6ecec;color:#52615f}
.di-chip.combo{background:#fff0c9;color:#7a4b00}
.di-meta{display:inline-block;background:#fdf3dc;color:#7a4b00;border-radius:9px;padding:0 9px;margin:0 0 4px 6px;font-size:11.8px;font-weight:800}
.di-foot{flex:none;display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:7px 16px 9px;font-size:11.5px;font-weight:700;color:#4a6764;border-top:1px solid #d3e5e2;background:#f4faf9}
.di-src{background:#e3f1ee;border-radius:8px;padding:0 8px;direction:ltr}
.di-foot .di-chip{font-size:11px}
.di-regen{margin-inline-start:auto;border:1px solid #b5d3ce;background:#fff;color:#0f766e;font:inherit;font-weight:900;font-size:11.5px;border-radius:9px;padding:3px 11px;cursor:pointer}
.di-regen:hover{background:#e3f1ee}
.di-caret{display:inline-block;width:2px;height:1em;background:#14b8a6;margin:0 2px;vertical-align:-2px;animation:diBlink .8s steps(1) infinite}
.di-load{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;text-align:center;padding:30px}
.di-spin{width:54px;height:54px;border-radius:50%;border:5px solid #cfe5e1;border-top-color:#14b8a6;animation:diSpin 1s linear infinite}
.di-lmsg{font-size:16px;font-weight:900;color:#0f766e}
.di-lsub{font-size:12.5px;font-weight:700;color:#4a6764;max-width:420px;line-height:1.8}
.di-err{background:#fff;border:1.5px solid #f3b4b4;color:#b91c1c;border-radius:14px;padding:14px 18px;font-weight:800;line-height:1.9;max-width:640px;direction:rtl;word-break:break-word}
.di-retry{border:0;background:#14b8a6;color:#fff;font:inherit;font-weight:900;border-radius:11px;padding:9px 22px;cursor:pointer}
@media (max-width:1000px){.di-grid{grid-template-columns:repeat(2,minmax(0,1fr));grid-template-rows:repeat(3,minmax(0,1fr));overflow:auto}.di-top{flex-wrap:wrap}}
`;
    document.head.append(st);
  }

  /* ── الكتابة التدريجية: تظهر كل النصوص بالترتيب، والنقر على أي مكان يُظهرها فوراً ── */
  function typeInto(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = []; let n;
    while ((n = walker.nextNode())) {
      if (!n.nodeValue.trim()) continue;
      if (n.parentNode && n.parentNode.closest && n.parentNode.closest('button')) continue;
      nodes.push({ n, t: n.nodeValue });
    }
    const parents = [...new Set(nodes.map(o => o.n.parentNode))];
    parents.forEach(x => { x.style.visibility = 'hidden'; });
    nodes.forEach(o => { o.n.nodeValue = ''; });
    const total = nodes.reduce((s, o) => s + o.t.length, 0);
    const perFrame = Math.max(3, Math.ceil(total / 300));
    const caret = document.createElement('span'); caret.className = 'di-caret';
    let i = 0, c = 0, raf = 0, done = false;
    const finish = () => {
      if (done) return; done = true; cancelAnimationFrame(raf);
      nodes.forEach(o => { o.n.nodeValue = o.t; });
      parents.forEach(x => { x.style.visibility = ''; });
      caret.remove();
    };
    const step = () => {
      if (done) return;
      let k = perFrame;
      while (k > 0 && i < nodes.length) {
        const o = nodes[i];
        if (o.n.parentNode.style.visibility === 'hidden') o.n.parentNode.style.visibility = '';
        const take = Math.min(k, o.t.length - c);
        c += take; k -= take; o.n.nodeValue = o.t.slice(0, c);
        if (c >= o.t.length) { i++; c = 0; }
      }
      if (i >= nodes.length) { finish(); return; }
      const cur = nodes[i].n;
      if (cur.parentNode) cur.parentNode.insertBefore(caret, cur.nextSibling);
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return { finish };
  }

  /* ── التصميم: كل الفقرات في شاشة واحدة ── */
  function render(p, ps, rec, onAgain) {
    const d = rec.data || {};
    const combo = ps.length > 1;
    const li = t => S(t) ? h('div', { class: 'di-li' }, S(t)) : null;
    const para = t => S(t) ? h('div', { class: 'di-p' }, S(t)) : null;
    const group = (label, arr, cls = '') => { const a = A(arr).map(S).filter(Boolean); return a.length ? [h('div', { class: 'di-lab ' + cls }, label), a.map(li)] : []; };
    const card = (c, title, ic, kids) => h('section', { class: 'di-card ' + c },
      h('header', {}, h('span', { html: icon(ic) }), h('b', {}, title)),
      h('div', { class: 'di-cb' }, kids));
    const chip = s => {
      const m = { safe: ['آمن', 'ok'], caution: ['بحذر', 'warn'], unsafe: ['ممنوع', 'bad'] }[S(s).toLowerCase()] || ['غير مؤكد', 'na'];
      return h('span', { class: 'di-chip ' + m[1] }, m[0]);
    };
    const obj = x => (x && typeof x === 'object') ? x : {};

    const brands = A(d.brands).map(b => (b && typeof b === 'object') ? { n: S(b.n), c: S(b.c) } : { n: S(b), c: '' }).filter(b => b.n);
    const top = h('div', { class: 'di-top' },
      h('div', { class: 'di-id' },
        h('div', { class: 'di-svg', html: capsule() }),
        h('div', { style: { minWidth: 0 } },
          h('div', { class: 'di-lbl' }, 'الاسم التجاري (من النظام)'),
          h('div', { class: 'di-trade' }, S(p.brandName), p.company ? h('small', {}, S(p.company)) : null),
          h('div', { class: 'di-lbl', style: { marginTop: '4px' } }, 'الاسم العلمي'),
          h('div', { class: 'di-sci' }, combo ? ps.join(' + ') : S(p.scientificName), combo ? h('span', { class: 'di-chip combo' }, 'تركيبة دوائية') : null))),
      h('div', { class: 'di-brands' },
        h('div', { class: 'di-lbl' }, 'الأسماء الشائعة في العراق (المكتوبة بالوصفات)'),
        h('div', { class: 'di-bl' }, brands.length
          ? brands.map(b => h('span', { class: 'di-bchip' }, b.n, b.c ? h('small', {}, b.c) : null))
          : h('span', { class: 'di-lbl' }, 'لا توجد أسماء مؤكدة'))));

    const uses = obj(d.uses), moa = obj(d.moa), adv = obj(d.adv), safe = obj(d.safe), extra = obj(d.extra);
    const doses = A(d.doses).map(x => (x && typeof x === 'object') ? x : { f: S(x) });
    const SAFE_ROWS = [['preg', 'الحامل'], ['lact', 'المرضعة'], ['child', 'الأطفال'], ['htn', 'مريض الضغط'], ['dm', 'مريض السكري'], ['kid', 'مريض الكلى'], ['liv', 'مريض الكبد'], ['heart', 'مريض القلب']];

    const grid = h('div', { class: 'di-grid' },
      card('c1', 'الاستخدامات', 'check', [para(uses.sum), A(uses.list).map(li)]),
      card('c2', 'الجرعات وطريقة الإعطاء', 'pill', doses.length ? doses.map(x => h('div', { class: 'di-dose' },
        h('div', { class: 'di-dh' }, S(x.f) + (S(x.who) ? ' — ' + S(x.who) : '')),
        S(x.d) ? h('div', {}, 'الجرعة: ' + S(x.d)) : null,
        S(x.how) ? h('div', {}, 'الإعطاء: ' + S(x.how)) : null,
        S(x.tip) ? h('div', { class: 'di-tip' }, 'نصيحة: ' + S(x.tip)) : null)) : para('غير مؤكد')),
      card('c3', 'آلية العمل (Mechanism of Action)', 'refresh', [para(moa.sum), A(moa.steps).map(li)]),
      card('c4', 'الآثار الجانبية وموانع الصرف', 'warn', [
        group('آثار شائعة', adv.common),
        group('آثار خطيرة — تستدعي مراجعة الطبيب', adv.serious, 'bad'),
        group('ممنوع الصرف / موانع الاستعمال', adv.contra, 'bad')]),
      card('c5', 'الأمان للحالات الخاصة', 'users', SAFE_ROWS.map(([k, label]) => {
        const o = obj(safe[k]);
        const txt = (k === 'child' && S(o.age) ? 'العمر: ' + S(o.age) + (S(o.t) ? ' — ' : '') : '') + S(o.t);
        return h('div', { class: 'di-srow' }, h('b', {}, label), chip(o.s), h('span', {}, txt));
      })),
      card('c6', 'تفاصيل أخرى مهمة', 'star', [
        S(extra.cls) ? h('span', { class: 'di-meta' }, 'الفئة: ' + S(extra.cls)) : null,
        S(extra.onset) ? h('span', { class: 'di-meta' }, 'بدء التأثير: ' + S(extra.onset)) : null,
        S(extra.half) ? h('span', { class: 'di-meta' }, 'عمر النصف: ' + S(extra.half)) : null,
        group('التداخلات الدوائية المهمة', extra.inter),
        group('نصائح للمريض', extra.tips),
        S(extra.store) ? h('div', { class: 'di-lab' }, 'التخزين') : null,
        S(extra.store) ? para(extra.store) : null]));

    const hostOf = s => { const t = S(s.t); if (t) return t; try { return new URL(s.u).hostname.replace(/^www\./, ''); } catch (_) { return ''; } };
    const srcs = [...new Set(A(rec.sources).map(hostOf).filter(Boolean))].slice(0, 6);
    const foot = h('div', { class: 'di-foot' },
      rec.grounded ? h('span', { class: 'di-chip ok' }, 'موثّق ببحث ويب') : h('span', { class: 'di-chip warn' }, 'بلا مصادر ويب — راجع النشرة الدوائية'),
      srcs.length ? h('span', {}, 'المصادر:') : null,
      srcs.map(s => h('span', { class: 'di-src' }, s)),
      h('span', {}, 'حُفظ: ' + fmtDate(rec.createdAt)),
      h('button', { class: 'di-regen', onclick: onAgain }, 'تحديث بالذكاء الاصطناعي'),
      h('button', { class: 'di-regen', style: { marginInlineStart: '0' }, onclick: () => KeyPool.openManager() }, 'المفاتيح'));

    return [top, grid, foot];
  }

  /* ── الفتح ── */
  async function open(p) {
    const sci = S(p.scientificName);
    if (!sci) return toast('أدخل الاسم العلمي للصنف أولاً من «تعديل الصنف»', 'r');
    const ps = splitParts(sci), key = keyOf(ps);
    if (!key) return toast('الاسم العلمي غير صالح للبحث', 'r');
    css();
    let alive = true, typer = null, tm = 0;
    const root = h('div', { class: 'di-root' });
    const m = openModal({ title: 'الموسوعة الدوائية الذكية', icon: 'pill', body: root, noPad: true,
      onClose: () => { alive = false; clearInterval(tm); if (typer) typer.finish(); } });
    m.box.classList.add('di-box');
    root.addEventListener('click', () => { if (typer) typer.finish(); });

    const loading = (msg, sub) => {
      clearInterval(tm);
      root.innerHTML = '';
      root.append(h('div', { class: 'di-load' }, h('div', { class: 'di-spin' }), h('div', { class: 'di-lmsg', id: 'di-lmsg' }, msg), h('div', { class: 'di-lsub' }, sub || '')));
    };
    const show = rec => {
      if (!alive) return;
      clearInterval(tm);
      root.innerHTML = '';
      root.append(...render(p, ps, rec, again));
      typer = typeInto(root);
    };
    const fail = e => {
      if (!alive) return;
      clearInterval(tm);
      root.innerHTML = '';
      root.append(h('div', { class: 'di-load' },
        h('div', { class: 'di-err' }, (e && e.message) || 'تعذّر جلب المعلومات'),
        h('button', { class: 'di-retry', onclick: () => run(false) }, 'إعادة المحاولة'),
        h('button', { class: 'di-regen', style: { margin: '0' }, onclick: () => KeyPool.openManager() }, 'إدارة المفاتيح')));
    };
    const run = async force => {
      if (!alive) return;
      loading('جارٍ تحضير المعلومات…');
      try {
        let rec = force ? null : await lookup(key);
        if (!rec) {
          loading('جارٍ البحث في المصادر الطبية الموثوقة…', 'أول بحث عن هذا الدواء يستغرق من 20 إلى 90 ثانية، وبعدها يُخزَّن ويظهر فوراً لكل الأجهزة.');
          const steps = ['جارٍ البحث في المصادر الطبية الموثوقة…', 'جارٍ مطابقة المعلومات مع النشرات الدوائية الرسمية…', 'جارٍ التحقق من الجرعات والأمان…', 'جارٍ ترتيب المعلومات…'];
          let si = 0;
          tm = setInterval(() => { const el = root.querySelector('#di-lmsg'); si = (si + 1) % steps.length; if (el) el.textContent = steps[si]; }, 7000);
          if (inflight.has(key)) rec = await inflight.get(key);
          else {
            const pr = generate(p, ps, key);
            inflight.set(key, pr);
            try { rec = await pr; } finally { inflight.delete(key); }
            await store(rec);
          }
        }
        show(rec);
      } catch (e) { fail(e); }
    };
    const again = async () => {
      if (!(await confirmBox('سيُستهلك من الحصة اليومية للمفتاح ويستبدل المعلومات المخزنة لهذا الدواء في كل الأجهزة. متابعة؟', { okLabel: 'تحديث' }))) return;
      run(true);
    };
    run(false);
  }

  function button(p) {
    css();
    return h('button', { class: 'di-3d', title: 'معلومات الدواء الذكية', 'aria-label': 'معلومات الدواء الذكية', html: capsule(), onclick: () => open(p) });
  }

  return { button, open };
})();

/* ───────────────────────── 21) تفاصيل الصنف + حركة المادة ───────────────────────── */
function renderProductDetails(tab) {
  const p = findProd(tab.props.productId);
  if (!p) { tab.el.append(h('div', { class: 'empty-note' }, 'الصنف غير موجود')); return; }
  const st = tab.state;
    st.f = st.f || { from: dateStr(Date.now() - 30 * 864e5), to: dateStr() }; // الافتراضي: آخر 30 يوماً
  const cBase = p.purchasePriceTop / (baseFactor(p) || 1);
  const page = h('div', { class: 'page', style: { overflowY: 'auto' } });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('pill') }), p.brandName , coTag(p)),
    p.featured ? h('span', { class: 'badge g' }, 'مميز') : null,
    DrugInfo.button(p),
    h('div', { class: 'spacer' }),
    h('button', { class: 'btn b', onclick: () => openTab('product', { productId: p.id }) }, h('span', { html: icon('edit') }), 'تعديل الصنف')));
  page.append(h('div', { class: 'stat-cards' },
    h('div', { class: 'sum-card n' }, h('label', {}, 'الاسم العلمي'), h('b', { style: { fontSize: '15px' } }, p.scientificName || '—')),
    h('div', { class: 'sum-card n' }, h('label', {}, 'الشكل / الجرعة'), h('b', { style: { fontSize: '15px' } }, `${p.form || '—'} ${p.dose || ''}`)),
    h('div', { class: 'sum-card b' }, h('label', {}, 'شراء الوحدة الصغرى'), h('b', {}, fmt(cBase))),
    h('div', { class: 'sum-card g' }, h('label', {}, 'بيع الوحدة الصغرى'), h('b', {}, fmt(p.salePriceBase))),
    h('div', { class: 'sum-card ' + ((p.stockBase || 0) <= (state.settings.lowStock ?? 10) ? 'r' : 'g') }, h('label', {}, 'المخزون الحالي'), h('b', {}, `${fmt(p.stockBase || 0)} ${smallUnitName(p)}`)),
    h('div', { class: 'sum-card n' }, h('label', {}, 'الإكسباير'), h('b', {}, p.expiry || '—'))));
  page.append(h('div', { class: 'det-meta' },
    h('div', { class: 'det-cell' }, h('label', {}, 'الباركودات'),
      h('div', { class: 'barcode-list' }, (p.barcodes || []).map(b =>
        h('span', { class: 'barcode-chip clickable', title: 'اضغط لطباعة ملصق هذا الباركود', onclick: () => openBarcodePrint(p, b) }, b)))),
    h('div', { class: 'det-cell' }, h('label', {}, 'التعبئة والأرصدة'),
      h('div', { class: 'price-preview' }, p.units.map((u, i) =>
        h('span', { class: 'price-chip' }, `${u.name} ×${unitFactor(p, i)}`, h('b', {}, `${fmt(stockInUnit(p, i))} متوفر`)))))));

  /* حركة المادة */
  const fromI = h('input', { type: 'date', value: st.f.from }), toI = h('input', { type: 'date', value: st.f.to });
  fromI.addEventListener('change', () => { st.f.from = fromI.value; drawMov(); });
  toI.addEventListener('change', () => { st.f.to = toI.value; drawMov(); });
  const movBox = h('div', { class: 'page-body det-mov' });
    page.append(h('div', { class: 'filter-bar', style: { marginTop: '4px' } },
    h('span', { html: icon('history'), style: { color: 'var(--green)', display: 'flex' } }),
    h('label', { style: { fontWeight: 900 } }, 'حركة المادة'),
    h('div', { class: 'f-group' }, h('label', {}, 'من'), fromI, h('label', {}, 'إلى'), toI),
    h('button', { class: 'btn n', style: { padding: '7px 14px', fontSize: '12.5px' }, onclick: () => { st.f.from = ''; st.f.to = ''; fromI.value = ''; toI.value = ''; drawMov(); } }, 'منذ بداية النظام')));
    page.append(movBox);
      function drawMov() {
    const all = [];
    state.sales.forEach(s => (s.items || []).forEach(it => {
      if (it.productId !== p.id) return;
      all.push({ ts: s.ts, date: s.date, kind: s.type === 'sale' ? 'بيع' : 'استرجاع بيع', emp: s.employeeName,
        qty: s.type === 'sale' ? -it.qty : it.qty, qtyBase: s.type === 'sale' ? -it.qtyBase : it.qtyBase,
        price: it.sale, docType: 'sale', docId: s.id });
    }));
    state.purchases.forEach(pu => (pu.items || []).forEach(it => {
      if (pu.deleted || it.productId !== p.id) return;
      all.push({ ts: pu.ts, date: pu.date, kind: pu.type === 'purchase' ? 'شراء' : 'استرجاع شراء', emp: pu.employeeName,
        qty: pu.type === 'purchase' ? it.qty : -it.qty, qtyBase: pu.type === 'purchase' ? it.qtyBase : -it.qtyBase,
        price: it.buyPrice, docType: 'purchase', docId: pu.id });
    }));
    /* سجل التعديلات اليدوية على العدد (جرد افتتاحي + تعديل العدد) — يُسجَّل مع كل حفظ للصنف */
    (p.stockLog || []).forEach(g => all.push({ ts: g.ts, date: dateStr(g.ts),
    kind: g.kind === 'opening' ? 'رصيد افتتاحي' : g.kind === 'rename' ? 'تغيير اسم' : 'تعديل عدد', note: g.note || '', emp: g.empName || '—',
      qty: g.delta, qtyBase: g.delta, price: 0, docType: null, docId: null }));
    all.sort((a, b) => a.ts - b.ts);

    /* ★ الرصيد الافتتاحي الصحيح = المخزون الحالي ناقص مجموع كل الحركات (بلا أي ترشيح بالتاريخ) */
    const initial = Math.round(((p.stockBase || 0) - all.reduce((s, m) => s + m.qtyBase, 0)) * 100) / 100;

    /* الرصيد التراكمي يُحسب عبر كل الحركات، ثم يُعرض ما يقع داخل الفترة فقط */
    let cum = initial;
    const shown = [];
    all.forEach(m => { cum += m.qtyBase; if ((!st.f.from || m.date >= st.f.from) && (!st.f.to || m.date <= st.f.to)) shown.push({ ...m, cum }); });

    movBox.innerHTML = '';
    const tbody = h('tbody');
    if (initial) tbody.append(h('tr', {},
      h('td', {}, h('span', { class: 'badge n' }, 'رصيد افتتاحي')),
      h('td', {}, '—'), h('td', { class: 'mono' }, '—'), h('td', { class: 'mono' }, '—'),
      h('td', { class: 'td-num' }, fmt(initial)),
      h('td', { class: 'td-num', style: { fontWeight: 900 } }, fmt(initial)),
      h('td', { class: 'td-num' }, '—'), h('td', {}, '')));
        shown.forEach(m => {
      const isName = m.kind === 'تغيير اسم';
      tbody.append(h('tr', {},
        h('td', {}, h('span', { class: 'badge ' + (m.kind === 'بيع' ? 'g' : m.kind === 'شراء' ? 'b' : m.kind === 'تعديل عدد' ? 'amber' : (m.kind === 'رصيد افتتاحي' || isName) ? 'n' : 'r') }, m.kind)),
        h('td', {}, m.emp), h('td', { class: 'mono' }, fmtDate(m.ts)), h('td', { class: 'mono' }, fmtTime(m.ts)),
        h('td', { class: 'td-num', style: { color: m.qty >= 0 ? 'var(--green)' : 'var(--red)' } }, isName ? '—' : (m.qty >= 0 ? '+' : '') + fmt(m.qty)),
        h('td', { class: 'td-num', style: { fontWeight: 900 } }, fmt(m.cum)),
        isName ? h('td', { style: { fontSize: '12px', fontWeight: 800 } }, m.note) : h('td', { class: 'td-num td-sale' }, m.docType ? fmt(m.price) : '—'),
        h('td', {}, m.docId ? h('button', { class: 'icon-btn edit', html: icon('edit'), title: 'فتح القائمة للتعديل',
          onclick: () => openTab(m.docType === 'sale' ? 'editsale' : 'editpurch', m.docType === 'sale' ? { saleId: m.docId } : { purchaseId: m.docId }) }) : '')));
    });
    movBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'نوع العملية'), h('th', {}, 'الموظف'), h('th', {}, 'التاريخ'), h('th', {}, 'الوقت'),
        h('th', {}, `العدد (${smallUnitName(p)})`), h('th', {}, 'العدد التراكمي'), h('th', {}, 'سعر البيع / الشراء'), h('th', {}, 'تعديل'))), tbody)));
    if (!shown.length) movBox.append(h('div', { class: 'empty-note' }, 'لا حركات لهذا الصنف في الفترة المحددة'));
  }
  drawMov();
  tab.el.append(page);
}

/* إضافة مذخر مع رصيد افتتاحي (دين سابق قبل النظام) — موحّدة لكل الأزرار */
function openAddSupplierModal(onDone) {
  const nameInp = h('input', { placeholder: 'اسم المذخر / الشركة' });
  const debtInp = h('input', { type: 'number', min: 0, placeholder: '0' });
  openModal({
    title: 'إضافة مذخر جديد', icon: 'suppliers',
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('label', {}, 'اسم المذخر ', h('span', { class: 'req' }, '*')), nameInp),
      h('div', { class: 'f-field full' }, h('label', {}, 'الرصيد الافتتاحي — دين سابق علينا (اختياري)'), debtInp,
        h('div', { class: 'f-hint' }, 'إن كان للمذخر دين قديم قبل النظام فأدخله هنا؛ يظهر في كشف الحساب كرصيد افتتاحي ويُحسب ضمن الدين المتراكم'))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'إضافة', cls: 'g', icon: 'check', big: true, onClick: async c => {
        const name = nameInp.value.trim();
        if (!name) return toast('أدخل اسم المذخر', 'r');
        const opening = num(debtInp.value);
        const s = { id: uid(), name, debt: opening, openingDebt: opening, createdAt: Date.now() };
        await save('suppliers', s);
        c();
        toast(`تمت إضافة المذخر «${name}»${opening ? ` برصيد افتتاحي ${fmt(opening)} ${cur()}` : ''}`);
        if (onDone) onDone(s);
      } },
    ],
  });
  nameInp.focus();
}

/* ★ تعديل رصيد المجهز يدوياً: الفرق يُسجَّل في الرصيد الافتتاحي ثم يُعاد حساب الدين المتراكم كاملاً */
function openSupplierBalanceModal(sup, onDone) {
  const balInp = h('input', { type: 'number', step: 'any', value: sup.debt || 0 });
  openModal({
    title: `تعديل الرصيد — ${sup.name}`, icon: 'edit',
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card r', style: { textAlign: 'center' } }, h('label', {}, 'الرصيد الحالي'), h('b', {}, `${fmt(sup.debt || 0)} ${cur()}`))),
      h('div', { class: 'f-field full' }, h('label', {}, 'الرصيد الجديد الصحيح'), balInp,
        h('div', { class: 'f-hint' }, 'يُصحَّح عبر الرصيد الافتتاحي مع إعادة حساب كامل السجل — موجب = دين علينا، سالب = رصيد لنا'))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'حفظ الرصيد', cls: 'g', icon: 'check', big: true, onClick: async c => {
        const target = num(balInp.value);
        sup.openingDebt = (sup.openingDebt || 0) + (target - (sup.debt || 0));
        await save('suppliers', sup);
        await recomputeSupplierDebt(sup.id);
        c(); if (onDone) onDone();
        toast(`عُدّل رصيد «${sup.name}» إلى ${fmt(sup.debt || 0)} ${cur()}`);
      } },
    ],
  });
  setTimeout(() => { balInp.focus(); balInp.select(); }, 60);
}

/* ───────────────────────── 22) حسابات المجهزين ───────────────────────── */
function renderSuppliers(tab) {
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('suppliers') }), 'حسابات مجهزين'),
    h('div', { class: 'spacer' }),
        h('button', { class: 'btn g', onclick: () => openAddSupplierModal(() => renderTabContent(tab)) }, h('span', { html: icon('plus') }), 'إضافة مذخر')));
  const bodyBox = h('div', { class: 'page-body' });
  const tbody = h('tbody');
  state.suppliers.filter(s => !s.deleted).forEach(s => tbody.append(h('tr', {},
    h('td', { class: 'td-name' }, s.name),
    h('td', { class: 'td-num', style: { color: (s.debt || 0) > 0 ? 'var(--red)' : 'var(--green)', fontWeight: 900, fontSize: '15px' } }, animSpan(s.debt || 0, ' ' + cur())),
    h('td', { class: 'td-num' }, s.lastPurchase ? fmt(s.lastPurchase.amount) : '—'),
    h('td', { class: 'mono' }, s.lastPurchase ? fmtDate(s.lastPurchase.ts) : '—'),
    h('td', { class: 'td-num', style: { color: 'var(--green)' } }, s.lastPayment ? fmt(s.lastPayment.amount) : '—'),
    h('td', { class: 'mono' }, s.lastPayment ? fmtDate(s.lastPayment.ts) : '—'),
    h('td', {}, h('div', { class: 'row-act' },
      h('button', { class: 'btn g', style: { padding: '8px 16px', fontSize: '13px' }, onclick: () => openPaymentModal(s.id) }, h('span', { html: icon('cash') }), 'تسديد'),
      h('button', { class: 'btn b', style: { padding: '8px 16px', fontSize: '13px' }, onclick: () => openSupplierBalanceModal(s, () => renderTabContent(tab)) }, h('span', { html: icon('edit') }), 'تعديل الرصيد'),
      h('button', { class: 'icon-btn del', title: 'حذف المذخر', html: icon('trash'), onclick: async () => {
        const yes = await confirmBox(`حذف المذخر «${s.name}»؟ (تبقى قوائمه محفوظة)`, { danger: true, okLabel: 'حذف' });
        if (yes) { s.deleted = true; await save('suppliers', s); renderTabContent(tab); }
      } }))),
  )));
  bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
    h('thead', {}, h('tr', {}, h('th', {}, 'اسم المذخر'), h('th', {}, 'الدين المتراكم'), h('th', {}, 'آخر عملية شراء'), h('th', {}, 'تاريخها'), h('th', {}, 'آخر تسديد'), h('th', {}, 'تاريخه'), h('th', {}, 'إجراء'))), tbody)));
  if (!state.suppliers.filter(s => !s.deleted).length) bodyBox.append(h('div', { class: 'empty-note' }, 'لا مذخرين بعد — أضفهم من الزر أعلاه أو من قائمة الشراء'));
  page.append(bodyBox);
  tab.el.append(page);
}
function openPaymentModal(supplierId) {
  let kind = 'payment'; // payment = تسديد (ينزل الدين) | deposit = إيداع (يرفع الرصيد لصالحنا)
  const supSel = h('select', { style: { width: '100%', border: '1.5px solid var(--line)', borderRadius: '12px', padding: '11px 14px', fontWeight: 800, outline: 'none' } },
    state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: s.id === supplierId }, s.name)));
  const debtEl = h('b', { style: { fontSize: '26px', color: 'var(--red)' } }, '0');
  const afterEl = h('b', { style: { fontSize: '17px' } }, '0');
  const amtInp = h('input', { type: 'number', min: 0, placeholder: '0' });
  const discAmt = h('input', { type: 'number', min: 0, placeholder: '0' });
  const discPct = h('input', { type: 'number', min: 0, placeholder: '0', style: { width: '80px' } });
  function current() { return (findSup(supSel.value) || { debt: 0 }).debt || 0; }
  function recalc(fromPct) {
    const amt = num(amtInp.value);
    if (fromPct) discAmt.value = Math.round(amt * num(discPct.value) / 100);
    else discPct.value = amt ? Math.round(num(discAmt.value) / amt * 1000) / 10 : 0;
    const total = amt + num(discAmt.value);
    const after = kind === 'payment' ? current() - total : current() - amt;
    animNum(afterEl, after, ' ' + cur());
    afterEl.style.color = after > 0 ? 'var(--red)' : 'var(--green)';
    animNum(debtEl, current(), ' ' + cur());
  }
  supSel.addEventListener('change', () => recalc());
  amtInp.addEventListener('input', () => recalc(true));
  discPct.addEventListener('input', () => recalc(true));
  discAmt.addEventListener('input', () => recalc(false));
  const kindBtns = h('div', { class: 'pay-row' },
    h('button', { class: 'pay-btn cash', style: { height: '46px', fontSize: '14px' }, onclick: function () { kind = 'payment'; selKind(this); recalc(); } }, 'تسديد (تخفيض الدين)'),
    h('button', { class: 'pay-btn electronic', style: { height: '46px', fontSize: '14px', opacity: .55 }, onclick: function () { kind = 'deposit'; selKind(this); recalc(); } }, 'إيداع (دفعة مقدمة)'));
  function selKind(btn) { $$('.pay-btn', kindBtns).forEach(b => b.style.opacity = .55); btn.style.opacity = 1; }
  openModal({
    title: 'تسديد المذخر', icon: 'cash', wide: true,
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('label', {}, 'المذخر'), supSel),
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card r', style: { textAlign: 'center' } }, h('label', {}, 'الدين المتراكم الحالي'), debtEl)),
      h('div', { class: 'f-field full' }, kindBtns),
      h('div', { class: 'f-field' }, h('label', {}, 'المبلغ المسدد ', h('span', { class: 'req' }, '*')), amtInp),
      h('div', { class: 'f-field' }, h('label', {}, 'الخصم الحاصل'), h('div', { class: 'input-group' }, discAmt, discPct, h('span', { style: { alignSelf: 'center', fontWeight: 900 } }, '%'))),
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card n', style: { textAlign: 'center' } }, h('label', {}, 'الدين بعد العملية'), afterEl))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'تنفيذ وحفظ', cls: 'g', icon: 'check', big: true, onClick: async c => {
        const amt = num(amtInp.value);
        if (!amt) return toast('أدخل المبلغ المسدد', 'r');
        const sup = findSup(supSel.value);
        const ts = Date.now(); const acc = me();
        const payDoc = { id: uid(), supplierId: sup.id, supplierName: sup.name, amount: amt, discount: num(discAmt.value),
          kind, employeeId: acc.id, employeeName: acc.name, ts, date: dateStr(ts), time: timeStr(ts) };
        sup.debt = kind === 'payment' ? (sup.debt || 0) - (amt + payDoc.discount) : (sup.debt || 0) - amt;
        payDoc.debtAfter = sup.debt;
        if (kind === 'payment') sup.lastPayment = { amount: amt, ts };
        await save('payments', payDoc);
        await save('suppliers', sup);
        c(); refreshActiveTab();
        toast(`تمت العملية — الدين الحالي: ${fmt(sup.debt)} ${cur()}`);
      } },
    ],
  });
  recalc();
  amtInp.focus();
}

/* ───────────────────────── 22-ب) الديون — حسابات الزبائن الآجلة ─────────────────────────
   كل زبون بيع له آجل له حساب: دينه المتراكم + تسديد يُنقص الدين ويوزَّع على فواتيره من الأقدم أولاً */
function renderDebts(tab) {
  const st = tab.state;
  st.q = st.q || '';
  const page = h('div', { class: 'page' });
  const qInp = h('input', { placeholder: 'ابحث باسم الزبون أو هاتفه…', value: st.q, autocomplete: 'off', style: { flex: 1, border: 'none', outline: 'none', fontWeight: 800 } });
  qInp.addEventListener('input', () => { st.q = qInp.value; draw(); });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('dollar') }), 'الديون — حسابات الآجل'),
    h('div', { class: 'spacer' }),
    h('div', { class: 'search-box', style: { height: '44px', maxWidth: '320px' } }, h('span', { html: icon('search') }), qInp)));
  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });
  page.append(bodyBox, footBox);
  function draw() {
    const q = st.q.trim().toLowerCase();
    const rows = state.customers
      .filter(c => !c.deleted && (c.debt || 0) > 0)
      .filter(c => !q || String(c.name).toLowerCase().includes(q) || String(c.phone || '').includes(q))
      .sort((a, b) => (b.debt || 0) - (a.debt || 0));
    bodyBox.innerHTML = ''; footBox.innerHTML = '';
    const tbody = h('tbody');
    rows.forEach(c => {
      const lists = state.sales.filter(s => s.type === 'sale' && s.pay === 'credit' && s.customerId === c.id && (s.remaining || 0) > 0).sort((a, b) => a.ts - b.ts);
      tbody.append(h('tr', {},
        h('td', { class: 'td-name' }, c.name, c.phone ? h('small', {}, c.phone) : null),
        h('td', { class: 'td-num' }, lists.length),
        h('td', { class: 'mono' }, lists.length ? fmtDate(lists[0].ts) : '—'),
        h('td', { class: 'td-num', style: { color: 'var(--red)', fontWeight: 900, fontSize: '16px' } }, animSpan(c.debt || 0, ' ' + cur())),
        h('td', {}, h('div', { class: 'row-act' },
          h('button', { class: 'btn g', style: { padding: '8px 16px', fontSize: '13px' }, onclick: () => openCustomerPayModal(c, () => renderTabContent(tab)) }, h('span', { html: icon('cash') }), 'تسديد'),
          h('button', { class: 'btn b', style: { padding: '8px 16px', fontSize: '13px' }, onclick: () => openCustomerStatement(c) }, h('span', { html: icon('receipt') }), 'كشف حساب')))));
    });
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'الزبون'), h('th', {}, 'فواتير عليها متبقٍ'), h('th', {}, 'أقدم فاتورة'), h('th', {}, 'الدين المتراكم'), h('th', {}, 'إجراء'))), tbody)));
    if (!rows.length) bodyBox.append(h('div', { class: 'empty-note' }, q ? 'لا نتائج مطابقة للبحث' : 'لا ديون مستحقة — كل الزبائن مسدّدون'));
    const total = state.customers.filter(c => !c.deleted).reduce((s, c) => s + (c.debt || 0), 0);
    const debtors = state.customers.filter(c => !c.deleted && (c.debt || 0) > 0).length;
    footBox.append(
      h('div', { class: 'sum-card n' }, h('label', {}, 'زبائن عليهم دين'), h('b', {}, animSpan(debtors))),
      h('div', { class: 'sum-card big' }, h('label', {}, 'إجمالي الديون المستحقة'), h('b', {}, animSpan(total, ' ' + cur()))));
  }
  draw();
  tab.el.append(page);
}

/* تسديد دين زبون: لا يقبل أكثر من الدين، ويُوزَّع على فواتيره الآجلة من الأقدم للأحدث */
function openCustomerPayModal(cust, onDone) {
  const amtInp = h('input', { type: 'number', min: 0, step: 'any', placeholder: '0' });
  const debtEl = h('b', { style: { fontSize: '26px', color: 'var(--red)' } }, `${fmt(cust.debt || 0)} ${cur()}`);
  const afterEl = h('b', { style: { fontSize: '17px' } }, `${fmt(cust.debt || 0)} ${cur()}`);
  const recalc = () => {
    const after = (cust.debt || 0) - num(amtInp.value);
    animNum(afterEl, after, ' ' + cur());
    afterEl.style.color = after > 0 ? 'var(--red)' : 'var(--green)';
    animNum(debtEl, cust.debt || 0, ' ' + cur());
  };
  amtInp.addEventListener('input', recalc);
  openModal({
    title: `تسديد دين — ${cust.name}`, icon: 'cash',
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card r', style: { textAlign: 'center' } }, h('label', {}, 'الدين المتراكم الحالي'), debtEl)),
      h('div', { class: 'f-field full' }, h('label', {}, 'المبلغ المسدد ', h('span', { class: 'req' }, '*')), amtInp),
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card n', style: { textAlign: 'center' } }, h('label', {}, 'الدين بعد التسديد'), afterEl))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'تنفيذ وحفظ', cls: 'g', icon: 'check', big: true, onClick: async c => {
        let amt = num(amtInp.value);
        if (amt <= 0) return toast('أدخل المبلغ المسدد', 'r');
        if (amt > (cust.debt || 0)) amt = cust.debt || 0; // لا يُقبل أكثر من الدين
        const ts = Date.now(); const acc = me();
        await save('payments', { id: uid(), customerId: cust.id, customerName: cust.name, amount: amt, kind: 'customer',
          employeeId: acc.id, employeeName: acc.name, ts, date: dateStr(ts), time: timeStr(ts) });
        let left = amt;
        const openSales = state.sales.filter(s => s.type === 'sale' && s.pay === 'credit' && s.customerId === cust.id && (s.remaining || 0) > 0).sort((a, b) => a.ts - b.ts);
        for (const s of openSales) {
          if (left <= 0) break;
          const cut = Math.min(s.remaining, left);
          s.remaining -= cut; left -= cut;
          await save('sales', s);
        }
        cust.debt = (cust.debt || 0) - amt;
        await save('customers', cust);
        c(); if (onDone) onDone();
        toast(`تم تسديد ${fmt(amt)} ${cur()} من دين «${cust.name}» — المتبقي: ${fmt(cust.debt || 0)} ${cur()}`);
      } },
    ],
  });
  recalc();
  setTimeout(() => amtInp.focus(), 60);
}

/* كشف حساب زبون: كل فواتيره الآجلة وتسديداته برصيد متراكم متحرك */
function openCustomerStatement(cust) {
  const evs = [];
  state.sales.filter(s => s.type === 'sale' && s.pay === 'credit' && s.customerId === cust.id)
    .forEach(s => evs.push({ ts: s.ts, kind: 'sale', doc: s, amount: (s.net || 0) - (s.paid || 0) }));
  state.payments.filter(p => p.kind === 'customer' && p.customerId === cust.id && !p.deleted)
    .forEach(p => evs.push({ ts: p.ts, kind: 'pay', doc: p, amount: p.amount }));
  evs.sort((a, b) => a.ts - b.ts);
  let run = 0; evs.forEach(e => { run += e.kind === 'sale' ? e.amount : -e.amount; e.after = run; });
  const tbody = h('tbody');
  [...evs].reverse().forEach(e => tbody.append(h('tr', {},
    h('td', {}, h('span', { class: 'badge ' + (e.kind === 'sale' ? 'r' : 'g') }, e.kind === 'sale' ? 'فاتورة آجلة' : 'تسديد')),
    h('td', { class: 'mono' }, fmtDate(e.ts)), h('td', { class: 'mono' }, fmtTime(e.ts)),
    h('td', {}, e.doc.employeeName || '—'),
    h('td', { class: 'td-num', style: { color: e.kind === 'sale' ? 'var(--red)' : 'var(--green)' } }, `${e.kind === 'sale' ? '+' : '−'} ${fmt(e.amount)}`),
    h('td', { class: 'td-num', style: { fontWeight: 900, color: e.after > 0 ? 'var(--red)' : 'var(--green)' } }, fmt(e.after)))));
  openModal({
    title: `كشف حساب — ${cust.name}`, icon: 'receipt', xwide: true,
    body: h('div', {},
      h('div', { class: 'sum-card r', style: { textAlign: 'center', marginBottom: '14px' } }, h('label', {}, 'الدين المتراكم الحالي'), h('b', {}, animSpan(cust.debt || 0, ' ' + cur()))),
      evs.length ? h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, h('th', {}, 'العملية'), h('th', {}, 'التاريخ'), h('th', {}, 'الوقت'), h('th', {}, 'الموظف'), h('th', {}, 'المبلغ'), h('th', {}, 'الرصيد المتراكم'))), tbody))
        : h('div', { class: 'empty-note' }, 'لا حركات آجلة لهذا الزبون بعد')),
  });
}

/* ───────────────────────── 23) الإعدادات ───────────────────────── */
function renderSettings(tab) {
  const st = tab.state;
  st.section = st.section || 'profile';
  const acc = me();
  const page = h('div', { class: 'page', style: { overflowY: 'auto' } });
  page.append(h('div', { class: 'page-head' }, h('div', { class: 'page-title' }, h('span', { html: icon('settings') }), 'الإعدادات')));
    const SECTIONS = [['profile','حسابي'],['pharmacy','الصيدلية والنظام'],['printer','الطابعة والملصقات'],['studio','استوديو التصميم'],['accounts','إدارة الحسابات'],['companies','الشركات'],['scanner','الماسح الذكي'],['backup','النسخ الاحتياطي']];
    const nav = h('div', { class: 'settings-nav' }, SECTIONS // الصلاحيات مفتوحة: كل الحسابات ترى كل الأقسام حالياً (بطلبك)
    .map(([k, l]) => h('div', { class: 'set-chip' + (st.section === k ? ' active' : ''), onclick: () => { st.section = k; renderTabContent(tab); } }, l)));
  page.append(nav);
  const box = h('div', { class: 'page-body', style: { padding: '20px', overflowY: 'auto' } });
  page.append(box);

  if (st.section === 'profile') {
    const nameInp = h('input', { value: acc.name });
        const passInp = h('input', { type: 'password', placeholder: 'اتركه فارغاً لإبقاء الحالية', autocomplete: 'new-password', dir: 'ltr' });
    const fileInp = h('input', { type: 'file', accept: 'image/*' });
    let photo = acc.photo;
        const apInner = h('div', { class: 'ap-inner' }, avatarNode(acc));
        fileInp.addEventListener('change', () => readAvatarFile(fileInp, data => {
      photo = data; apInner.innerHTML = ''; apInner.append(avatarNode({ photo, gender: acc.gender }));
    }));
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '560px' } },
      h('div', { class: 'f-field full' }, h('div', { class: 'avatar-preview' },
        h('div', { class: 'ap-frame' }, apInner, h('label', { class: 'ap-edit', html: icon('camera') }, fileInp)))),
      h('div', { class: 'f-field' }, h('label', {}, 'اسم الحساب'), nameInp),
      h('div', { class: 'f-field' }, h('label', {}, 'كلمة المرور'), passInp),
      h('div', { class: 'f-field full' },
                h('button', { class: 'btn g', onclick: async () => {
          const n = nameInp.value.trim(), pw = passInp.value;
          if (!n) return toast('أدخل اسم الحساب', 'r');
          acc.name = n; acc.photo = photo;
          if (pw.trim()) await setPassword(acc, pw); // فارغ = لا تغيير على كلمة المرور
          await save('accounts', acc);
          renderTopbar(); toast('تم حفظ بيانات حسابك');
        } }, h('span', { html: icon('check') }), 'حفظ التعديلات'))));
   }     
  else if (st.section === 'pharmacy') {
    const phInp = h('input', { value: state.settings.pharmacyName });
    const pctInp = h('input', { type: 'number', min: 0, value: state.settings.profitPct ?? 30 });
    const lowInp = h('input', { type: 'number', min: 0, value: state.settings.lowStock ?? 10 });
    const curInp = h('input', { value: state.settings.currency || 'د.ع' });
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '620px' } },
      h('div', { class: 'f-field' }, h('label', {}, 'اسم الصيدلية'), phInp),
      h('div', { class: 'f-field' }, h('label', {}, 'العملة'), curInp),
      h('div', { class: 'f-field' }, h('label', {}, 'نسبة الربح الافتراضية %'), pctInp, h('div', { class: 'f-hint' }, 'تُطبق تلقائياً عند إضافة صنف جديد')),
      h('div', { class: 'f-field' }, h('label', {}, 'حد النواقص (بالوحدة الصغرى)'), lowInp, h('div', { class: 'f-hint' }, 'تنبيه عند بلوغ المخزون هذا الحد')),
      h('div', { class: 'f-field full' },
        h('button', { class: 'btn g', onclick: async () => {
          state.settings.pharmacyName = phInp.value.trim() || 'صيدلية درب الشفاء';
          state.settings.profitPct = num(pctInp.value);
          state.settings.lowStock = num(lowInp.value);
          state.settings.currency = curInp.value.trim() || 'د.ع';
          await save('settings', state.settings);
          renderTopbar(); renderSideNav(); toast('تم حفظ إعدادات النظام');
        } }, h('span', { html: icon('check') }), 'حفظ الإعدادات'))));
  }
    else if (st.section === 'printer') {
    /* ★ إعدادات طابعة الملصقات: كل شيء من داخل التطبيق — الطباعة بعدها صامتة بضغطة واحدة */
    state.settings.printer = state.settings.printer || { name: '', w: 38, h: 25 };
    state.settings.invoicePrinter = state.settings.invoicePrinter || { name: '' };
    const pr = state.settings.printer;
    const invPr = state.settings.invoicePrinter;
    const prSel = h('select', {}, h('option', { value: '' }, '— الطابعة الافتراضية للنظام —'));
    const invPrSel = h('select', {}, h('option', { value: '' }, '— الطابعة الافتراضية للنظام —'));
    const statusEl = h('div', { class: 'f-hint' }, 'جارٍ قراءة طابعات النظام…');
    (async () => {
      if (!(window.desktop && window.desktop.print)) { statusEl.textContent = 'قائمة الطابعات متاحة داخل تطبيق سطح المكتب فقط'; return; }
      const list = await window.desktop.print.list();
      statusEl.textContent = list.length ? `تم العثور على ${list.length} طابعة في النظام` : 'لم يُعثر على أي طابعة مثبتة';
      list.forEach(x => prSel.append(h('option', { value: x.name, selected: pr.name === x.name },
        x.name + (x.isDefault ? ' (افتراضية)' : ''))));
      list.forEach(x => invPrSel.append(h('option', { value: x.name, selected: invPr.name === x.name },
        x.name + (x.isDefault ? ' (افتراضية)' : ''))));
    })();
    const wInp = h('input', { type: 'number', min: 20, max: 120, value: pr.w || 38 });
    const hInp = h('input', { type: 'number', min: 10, max: 120, value: pr.h || 25 });
    const savePr = async () => {
      pr.name = prSel.value; pr.w = num(wInp.value) || 38; pr.h = num(hInp.value) || 25;
      invPr.name = invPrSel.value;
      await save('settings', state.settings);
    };
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '620px' } },
      h('div', { class: 'f-field full' }, h('label', {}, 'طابعة الملصقات (Xprinter)'), prSel, statusEl),
      h('div', { class: 'f-field' }, h('label', {}, 'عرض الملصق (مم)'), wInp),
      h('div', { class: 'f-field' }, h('label', {}, 'ارتفاع الملصق (مم)'), hInp),
      h('div', { class: 'f-field full' }, h('label', {}, 'طابعة الفواتير (80مم)'), invPrSel,
        h('div', { class: 'f-hint' }, 'تُطبع عليها فاتورة البيع المصمَّمة في «استوديو التصميم». التشغيل/الإيقاف من مفتاح الطباعة بجانب الخصم في نقطة البيع.')),
      h('div', { class: 'f-field full' }, h('div', { class: 'f-hint' },
        'لملصقاتك الحالية: العرض 38 والارتفاع 25. الاتجاه يُفرض عمودياً تلقائياً لكل ملصق — لن تُطبع صفحة عرضية ولن يُهدر أي ملصق. تأكد أيضاً أن مقاس الورق في تعريف الطابعة بويندوز هو 38×25مم.')),
      h('div', { class: 'f-field full', style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
        h('button', { class: 'btn g', onclick: async () => { await savePr(); toast('حُفظت إعدادات الطابعة — الطباعة الآن صامتة دائماً'); } },
          h('span', { html: icon('check') }), 'حفظ إعدادات الطابعة'),
        h('button', { class: 'btn b', onclick: async () => { await savePr(); printBarcodeLabels('اختبار طباعة — ' + (state.settings.pharmacyName || ''), '000001', 1); } },
          h('span', { html: icon('print') }), 'طباعة ملصق تجريبي'),
        h('button', { class: 'btn b', onclick: async () => { await savePr(); printSaleInvoice(invDemoSale()); } },
          h('span', { html: icon('receipt') }), 'طباعة فاتورة تجريبية'),
        h('button', { class: 'btn n', onclick: () => { st.section = 'studio'; renderTabContent(tab); } },
          h('span', { html: icon('edit') }), 'فتح استوديو التصميم'))));
  }
  else if (st.section === 'accounts') {
    const list = h('div', {});
    state.accounts.filter(a => !a.deleted).forEach(a => list.append(h('div', { class: 'inv-mini', style: { display: 'flex', alignItems: 'center', gap: '12px' } },
            accountAvatar(a, 38),
      h('div', { style: { flex: 1 } }, h('b', {}, a.name), ' ', a.role === 'admin' ? h('span', { class: 'badge b' }, 'مدير') : h('span', { class: 'badge n' }, 'موظف')),
      h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: async () => {
                const pw = await promptBox(`كلمة مرور جديدة لـ «${a.name}» — أي طول مسموح`, { type: 'password' });
        if (pw) { await setPassword(a, pw); await save('accounts', a); toast('تم تغيير كلمة المرور'); }
      } }, 'تغيير كلمة المرور'),
      a.role !== 'admin' ? h('button', { class: 'mini-btn ' + (a.role === 'admin' ? 'n' : 'green'), style: { flex: 'none' }, onclick: async () => {
        a.role = a.role === 'admin' ? 'staff' : 'admin';
        await save('accounts', a); renderTabContent(tab);
      } }, a.role === 'admin' ? 'إلغاء الإدارة' : 'جعله مديراً') : null,
      a.id !== acc.id ? h('button', { class: 'mini-btn red', style: { flex: 'none' }, onclick: async () => {
        const yes = await confirmBox(`حذف حساب «${a.name}» نهائياً؟`, { danger: true, okLabel: 'حذف' });
        if (yes) { a.deleted = true; await save('accounts', a); renderTabContent(tab); toast('تم حذف الحساب', 'b'); }
      } }, 'حذف') : h('span', { class: 'badge g' }, 'أنت'))));
    box.append(h('h4', { style: { fontWeight: 900, marginBottom: '12px' } }, 'الحسابات المسجلة'), list);
  }
    else if (st.section === 'companies') {
    if (!Array.isArray(state.settings.companies) || !state.settings.companies.length)
      state.settings.companies = DEFAULT_COMPANIES.map(c => ({ ...c }));
    const qInp = h('input', { placeholder: 'ابحث عن شركة…', style: { width: '100%', border: '1.5px solid var(--line)', borderRadius: '12px', padding: '11px 14px', fontWeight: 800, outline: 'none' } });
    const list = h('div', {});
    const drawList = () => {
      list.innerHTML = '';
      const q = qInp.value.trim().toLowerCase();
      const arr = state.settings.companies.filter(c => !q || c.name.toLowerCase().includes(q));
      if (!arr.length) { list.append(h('div', { class: 'empty-note' }, 'لا نتائج')); return; }
      arr.forEach(c => list.append(h('div', { class: 'inv-mini', style: { display: 'flex', alignItems: 'center', gap: '12px' } },
        h('span', { html: icon('store'), style: { display: 'flex', color: 'var(--blue)' } }),
        h('div', { style: { flex: 1 } }, h('b', {}, c.name),
          c.country ? h('small', { style: { color: 'var(--muted)', fontWeight: 700, display: 'block' } }, c.country) : null),
        h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: async () => {
          const v = await promptBox('اسم الشركة', { value: c.name });
          if (!v) return;
          c.name = v.trim();
          await save('settings', state.settings); drawList(); toast('حُفظ التعديل');
        } }, 'تعديل'),
        h('button', { class: 'mini-btn red', style: { flex: 'none' }, onclick: async () => {
          const yes = await confirmBox(`حذف «${c.name}» من قائمة الشركات؟`, { danger: true, okLabel: 'حذف' });
          if (!yes) return;
          state.settings.companies = state.settings.companies.filter(x => x.name !== c.name);
          await save('settings', state.settings); drawList(); toast('حُذفت الشركة', 'b');
        } }, 'حذف'))));
    };
    qInp.addEventListener('input', drawList);
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '640px' } },
      h('div', { class: 'f-field full' }, h('label', {}, 'قائمة الشركات المصنعة'), qInp),
      h('div', { class: 'f-field full' }, list),
      h('div', { class: 'f-field full' }, h('span', { class: 'f-hint' },
        `الإجمالي: ${state.settings.companies.length} شركة — أي شركة تكتبها في صفحة الصنف أو يكتشفها الماسح تُضاف هنا تلقائياً`))));
    drawList();
  }
  else if (st.section === 'scanner') {
    const keyInp = h('input', { type: 'password', value: state.settings.geminiKey || '', placeholder: 'AIza...' });
    const testOut = h('div', { class: 'f-hint' });
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '680px' } },
      h('div', { class: 'f-field full' }, h('label', {}, 'مفتاح Gemini API (مجاني تماماً)'), keyInp,
        h('div', { class: 'f-hint' }, 'الصق المفتاح ثم اضغط «حفظ المفتاح». يبقى على هذا الجهاز فقط ولا يُرفع إلى السحابة إطلاقاً.')),
      h('div', { class: 'f-field full', style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
        h('button', { class: 'btn g', onclick: async () => {
          state.settings.geminiKey = keyInp.value.trim();
          await save('settings', state.settings);
          toast('تم حفظ المفتاح');
        } }, h('span', { html: icon('check') }), 'حفظ المفتاح'),
        h('button', { class: 'btn b', onclick: async () => {
          const k = keyInp.value.trim();
          if (!k) return toast('الصق المفتاح أولاً', 'r');
          testOut.textContent = 'جارٍ اختبار المفتاح…';
          try {
            const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(k)}`);
                        if (!r.ok) throw new Error(`HTTP ${r.status}`);
            const used = await InvoiceScanner.usableModels(k);
            testOut.innerHTML = `<b style="color:var(--green)">✓ المفتاح يعمل — الموديل المعتمد: ${esc(used[0])}</b>`;
            toast('المفتاح صالح');
          } catch (e) {
            testOut.innerHTML = `<b style="color:var(--red)">✗ المفتاح لا يعمل: ${(e && e.message) || e}</b>`;
          }
        } }, h('span', { html: icon('refresh') }), 'اختبار المفتاح')),
      h('div', { class: 'f-field full' }, testOut),
      h('div', { class: 'f-field full' },
        h('div', { class: 'sum-card n' }, h('label', {}, 'كيف تحصل على مفتاح مجاني للأبد (خطوة بخطوة)'),
          h('div', { style: { fontWeight: 700, lineHeight: 2.1, fontSize: '13px' } },
            h('div', {}, '1) افتح المتصفح على: aistudio.google.com/apikey'),
            h('div', {}, '2) سجّل الدخول بحساب Google عادي (لا يحتاج بطاقة بنكية ولا أي دفع).'),
            h('div', {}, '3) اضغط «Create API key» ثم اختر «Create API key in new project».'),
            h('div', {}, '4) انسخ المفتاح (يبدأ بـ AIza…) والصقه في الخانة أعلاه ثم اضغط «حفظ المفتاح».'),
            h('div', {}, '5) اضغط «اختبار المفتاح» للتأكد — ثم افتح الماسح من الزر أسفل.'),
            h('div', { style: { marginTop: '8px', color: 'var(--muted)' } }, 'المفتاح مجاني وثابت بلا انتهاء صلاحية، والحد المجاني يكفي فواتير الصيدلية اليومية بمرات. لا تشاركه مع أحد.')))),
      h('div', { class: 'f-field full', style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
        h('button', { class: 'btn b', onclick: () => openTab('scanner') }, h('span', { html: icon('camera') }), 'فتح الماسح الذكي'),
        h('button', { class: 'btn g', onclick: () => KeyPool.openManager() }, h('span', { html: icon('lock') }), 'مفاتيح الموسوعة الدوائية'))));
  }
  else if (st.section === 'studio') { renderDesignStudio(box); }
  else if (st.section === 'backup') {
    const fileInp = h('input', { type: 'file', accept: '.json', style: { display: 'none' } });
    fileInp.addEventListener('change', () => {
      const f = fileInp.files[0]; if (!f) return;
      const r = new FileReader();
      r.onload = async () => {
        try {
          const data = JSON.parse(r.result);
          for (const k of ['accounts','products','sales','purchases','suppliers','payments','customers']) if (data[k]) await DB.bulk(k, data[k]);
          if (data.settings) await DB.put('settings', data.settings);
          toast('تمت الاستعادة — سيُعاد تشغيل النظام', 'b');
          setTimeout(() => location.reload(), 1200);
        } catch (e) { toast('ملف غير صالح', 'r'); }
      };
      r.readAsText(f);
    });
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '560px' } },
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card g', style: { textAlign: 'center' } },
        h('label', {}, 'إحصائيات البيانات'),
        h('b', { style: { fontSize: '15px' } }, `${state.products.filter(p=>!p.deleted).length} صنف • ${state.sales.length} قائمة بيع • ${state.purchases.length} قائمة شراء • ${state.suppliers.filter(s=>!s.deleted).length} مذخر`))),
      h('div', { class: 'f-field full' }, h('button', { class: 'btn b big', onclick: async () => {
        const data = {};
        for (const k of ['accounts','products','sales','purchases','suppliers','payments','customers']) data[k] = await DB.all(k);
        data.settings = state.settings;
        const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
        const a = h('a', { href: URL.createObjectURL(blob), download: `نسخة-احتياطية-درب-الشفاء-${dateStr()}.json` });
        a.click();
        toast('تم تصدير النسخة الاحتياطية');
      } }, h('span', { html: icon('download') }), 'تصدير نسخة احتياطية كاملة')),
      h('div', { class: 'f-field full' }, h('button', { class: 'btn n big', onclick: () => fileInp.click() }, h('span', { html: icon('upload') }), 'استعادة من نسخة احتياطية'), fileInp),
            Sync.ready ? h('div', { class: 'f-field full' }, h('button', { class: 'btn g big', onclick: async () => {
        toast('جارٍ الرفع إلى السحابة…', 'b');
        const r = await Sync.uploadAll();
        if (r.code === 'not-ready') return toast('المزامنة غير جاهزة — لا اتصال بالسحابة', 'r');
        if (r.fail) return toast(`فشل رفع ${r.fail} من ${r.ok + r.fail} مستنداً — كود الخطأ: ${r.code}`, 'r');
        toast(`تم رفع ${r.ok} مستنداً إلى السحابة بنجاح`);
      } }, h('span', { html: icon('upload') }), 'رفع كل البيانات المحلية إلى السحابة')) : null));
  }
  tab.el.append(page);
}

/* ════════════════════════════════════════════════════════════════════
   استوديو تصميم الفاتورة — محرر مرئي لطابعات 80مم (ورق بطول مفتوح)
   الرأس والتذييل ثابتان، وجدول الأصناف يتمدد من الوسط بين خطّي «بداية/نهاية الجدول»
   ════════════════════════════════════════════════════════════════════ */
const INV_FONTS = ['Cairo','Alexandria','Tajawal','Almarai','Amiri','Changa','El Messiri','Noto Kufi Arabic','Lateef','Scheherazade New','Aref Ruqaa','Marhey'];
const INV_VARS = [
  ['pharmacyName','اسم الصيدلية'],['invNo','رقم الفاتورة'],['date','التاريخ'],['time','الوقت'],
  ['customerName','اسم الزبون'],['employeeName','الموظف'],['itemCount','عدد الأصناف'],
  ['subtotal','المجموع'],['discount','الخصم'],['net','المطلوب'],['paid','المدفوع'],['remaining','المتبقي']
];
const INV_COLS = [['التسلسل',7],['العلاج',26],['التعبئة',11],['العدد',9],['السعر',10],['المجموع',11]]; // العرض الكلي 74مم داخل ورقة 76مم

function invDefaultDesign() {
  let n = 0; const id = () => 'el' + Date.now().toString(36) + '_' + (n++);
  const txt = (t, y, size, bold, font, align) => ({ id: id(), t: 'text', x: 2, y, w: 76, h: Math.max(4, size * 0.55), txt: t, font: font || 'Cairo', size, bold: !!bold, color: '#111111', align: align || 'center' });
  const line = y => ({ id: id(), t: 'shape', shape: 'hline', x: 2, y, w: 76, h: 0.4, stroke: '#111111', fill: 'none', radius: 0 });
  return {
    pageW: 80, pageH: 92, tableTop: 33, tableBottom: 50, rowH: 6.5,
    elements: [
      txt('صيدلية درب الشفاء', 2, 15, true, 'Alexandria'),
      txt('{{date}}   {{time}}', 10.5, 9, false),
      txt('فاتورة رقم: {{invNo}}', 16, 9.5, true),
      txt('الزبون: {{customerName}}', 21.5, 9, false, 'Cairo', 'right'),
      txt('الكاشير: {{employeeName}}', 26.5, 9, false, 'Cairo', 'right'),
      line(31.8),
      line(51.4),
      txt('المجموع: {{subtotal}}', 52.6, 10, false, 'Cairo', 'right'),
      txt('الخصم: {{discount}}', 58.2, 10, false, 'Cairo', 'right'),
      txt('المطلوب: {{net}}', 63.8, 12.5, true, 'Alexandria', 'right'),
      txt('المدفوع: {{paid}}   المتبقي: {{remaining}}', 70.4, 9.5, false, 'Cairo', 'right'),
      line(76.4),
      txt('شكراً لثقتكم — نتمنى لكم دوام الصحة', 78, 9, false),
      txt('عدد الأصناف: {{itemCount}}', 84, 8.5, false),
    ]
  };
}
/* قراءة التصميم مع ترميم دفاعي (RTDB قد يحوّل مصفوفة العناصر إلى كائن مفهرس) */
function invDesign() {
  const raw = (state.settings && state.settings.invoiceDesign) || null;
  const d = (raw && typeof raw === 'object' && raw.elements) ? raw : invDefaultDesign();
  let els = d.elements; if (!Array.isArray(els)) els = els && typeof els === 'object' ? Object.values(els) : [];
  const cl = (v, lo, hi, df) => { v = +v; return isFinite(v) ? Math.min(hi, Math.max(lo, v)) : df; };
  const out = {
    pageW: cl(d.pageW, 50, 120, 80), pageH: cl(d.pageH, 40, 400, 92),
    tableTop: cl(d.tableTop, 4, 390, 33), tableBottom: cl(d.tableBottom, 6, 395, 50),
    rowH: cl(d.rowH, 4, 20, 6.5),
    elements: els.filter(e => e && typeof e === 'object').map(e => ({ ...e })),
  };
  if (out.tableBottom <= out.tableTop + 4) out.tableBottom = out.tableTop + 8;
  return out;
}
function invVarMap(sale) {
  const items = Array.isArray(sale.items) ? sale.items : [];
  const net = Math.max(0, (sale.subtotal || 0) - (sale.discount || 0));
  return {
    pharmacyName: (state.settings && state.settings.pharmacyName) || 'صيدلية درب الشفاء',
    invNo: String(sale.id || '').replace(/[^0-9a-zA-Z]/g, '').slice(-6).toUpperCase() || '—',
    date: sale.date || dateStr(sale.ts), time: fmtTime(sale.ts),
    customerName: sale.customerName || 'زبون نقدي', employeeName: sale.employeeName || '—',
    itemCount: items.length,
    subtotal: fmt(sale.subtotal || 0), discount: fmt(sale.discount || 0), net: fmt(net),
    paid: fmt(sale.paid != null ? sale.paid : net), remaining: fmt(sale.remaining || 0),
  };
}
/* بناء مستند الفاتورة: الرأس ثابت، التذييل ينزاح بمقدار تمدد الجدول، والطول مفتوح (قص تلقائي) */
function invBuildInvoice(sale) {
  const d = invDesign();
  const items = Array.isArray(sale.items) ? sale.items : [];
  const vals = invVarMap(sale);
  const fillVars = s => String(s == null ? '' : s).replace(/\{\{(\w+)\}\}/g, (m, k) => vals[k] != null ? esc(vals[k]) : m);
  const mm = n => (+n).toFixed(2) + 'mm';
  const tableH = d.rowH * (items.length + 1);
  const delta = Math.max(0, tableH - (d.tableBottom - d.tableTop)); // التمدد من الوسط فقط
  const elHtml = (e, yOff) => {
    const pos = `position:absolute;right:${mm(e.x || 0)};top:${mm((e.y || 0) + yOff)};width:${mm(e.w || 10)};height:${mm(e.h || 5)};box-sizing:border-box;`;
    if (e.t === 'img') return e.src ? `<img src="${esc(e.src)}" style="${pos}object-fit:contain;display:block" alt="">` : '';
    if (e.t === 'shape') {
      if (e.shape === 'hline') return `<div style="${pos}height:0;border-top:0.4mm solid ${esc(e.stroke || '#111')}"></div>`;
      if (e.shape === 'vline') return `<div style="${pos}width:0;border-right:0.4mm solid ${esc(e.stroke || '#111')}"></div>`;
      const rad = e.shape === 'ellipse' ? '50%' : (e.shape === 'rrect' ? mm(e.radius || 1.2) : '0');
      return `<div style="${pos}border:0.35mm solid ${esc(e.stroke || '#111')};border-radius:${rad};background:${e.fill && e.fill !== 'none' ? esc(e.fill) : 'transparent'}"></div>`;
    }
    return `<div style="${pos}font-family:'${esc(e.font || 'Cairo')}',sans-serif;font-size:${(+e.size || 9).toFixed(1)}pt;font-weight:${e.bold ? 800 : 400};color:${esc(e.color || '#111')};text-align:${e.align === 'right' ? 'right' : e.align === 'left' ? 'left' : 'center'};line-height:1.15;overflow:hidden;word-break:break-word">${fillVars(e.txt)}</div>`;
  };
  const center = e => (e.y || 0) + (e.h || 0) / 2;
  const header = d.elements.filter(e => center(e) < d.tableTop).map(e => elHtml(e, 0)).join('');
  const footer = d.elements.filter(e => center(e) >= d.tableBottom).map(e => elHtml(e, delta)).join('');
  /* جدول الأصناف: مستطيلات مدورة مرصوصة — العناوين بتعبئة غامقة قليلاً والخلايا رصاصي فاتح وكلها بتحديد أسود */
  const cellCss = `box-sizing:border-box;border:0.35mm solid #000;border-radius:1.1mm;margin:0.3mm;padding:0.4mm 0.6mm;display:flex;align-items:center;justify-content:center;text-align:center;overflow:hidden;line-height:1.1;font-size:8.5pt;font-family:'Cairo',sans-serif`;
  const rowHtml = (cells, hdr) => `<div style="display:flex;direction:rtl;height:${mm(d.rowH)}">${cells.map((c, i) =>
    `<div style="width:${mm(INV_COLS[i][1])};${cellCss};background:${hdr ? '#d9dee5' : '#f3f4f6'};font-weight:${hdr ? 800 : 400}">${c}</div>`).join('')}</div>`;
  let rowsHtml = rowHtml(INV_COLS.map(c => esc(c[0])), true);
  items.forEach((it, i) => {
    rowsHtml += rowHtml([String(i + 1), esc(it.name || ''), esc(it.unitName || ''), esc(fmt(it.qty)), esc(fmt(it.sale)), esc(fmt(it.total != null ? it.total : it.sale * it.qty))], false);
  });
  const table = `<div style="position:absolute;right:2mm;top:${mm(d.tableTop)};width:76mm">${rowsHtml}</div>`;
  const hMm = d.pageH + delta;
  const css = `*{margin:0;padding:0}html,body{background:#fff}.invpage{position:relative;width:${mm(d.pageW)};height:${mm(hMm)};background:#fff;direction:rtl;overflow:hidden}`;
  const body = `<div class="invpage">${header}${table}${footer}</div>`;
  const doc = `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline' https://fonts.googleapis.com;font-src https://fonts.gstatic.com;img-src data:">
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;800;900&family=Alexandria:wght@700;800;900&family=Tajawal:wght@400;700;800&family=Almarai:wght@400;700;800&family=Amiri:wght@400;700&family=Changa:wght@400;700;800&family=El+Messiri:wght@400;700&family=Noto+Kufi+Arabic:wght@400;700;800&family=Lateef:wght@400;700&family=Scheherazade+New:wght@400;700&family=Aref+Ruqaa:wght@400;700&family=Marhey:wght@400;700&display=swap" rel="stylesheet">
<style>${css}</style></head><body>${body}</body></html>`;
  return { doc, body, css, hMm, wMm: d.pageW };
}
/* فاتورة تجريبية للمعاينة والاختبار */
function invDemoSale() {
  const ts = Date.now();
  return {
    id: 'demo123456', type: 'sale', ts, date: dateStr(ts),
    customerName: 'زبون تجريبي', employeeName: (me() || {}).name || 'الموظف',
    subtotal: 23500, discount: 500, net: 23000, paid: 20000, remaining: 3000,
    items: [
      { name: 'بنادول إكسترا 24 قرص', unitName: 'علبة', qty: 2, sale: 3000, total: 6000 },
      { name: 'أموكسيسيلين 500mg كبسول', unitName: 'شريط', qty: 1, sale: 4500, total: 4500 },
      { name: 'فيتامين C فوار 1000', unitName: 'قطعة', qty: 3, sale: 2500, total: 7500 },
      { name: 'شراب كحة للأطفال 120ml', unitName: 'قنينة', qty: 1, sale: 5500, total: 5500 },
    ],
  };
}
/* سقوط المتصفح: طباعة عبر نافذة النظام بمقاس صفحة ديناميكي 80مم × الطول المحسوب */
function browserPrintInvoice(bodyHtml, css, hMm, wMm) {
  const old = document.getElementById('print-root'); if (old) old.remove();
  const oldSt = document.getElementById('inv-print-style'); if (oldSt) oldSt.remove();
  const st = h('style', { id: 'inv-print-style' });
  st.textContent = `@page{size:${wMm}mm ${Math.ceil(hMm)}mm;margin:0}\n@media print{#print-root{display:block;position:absolute;inset:0}}\n#print-root{width:${wMm}mm}\n` + css;
  document.head.append(st);
  const root = h('div', { id: 'print-root', class: 'print-area' });
  root.innerHTML = bodyHtml;
  document.body.append(root);
  setTimeout(() => { window.print(); setTimeout(() => { root.remove(); st.remove(); }, 600); }, 150);
}
/* طباعة الفاتورة: صامتة على طابعة الفواتير المختارة داخل Electron، وتسقط على نافذة النظام عند الفشل */
function printSaleInvoice(sale) {
  try {
    const { doc, body, css, hMm, wMm } = invBuildInvoice(sale);
    const devName = ((state.settings && state.settings.invoicePrinter) || {}).name || '';
    if (window.desktop && window.desktop.print && typeof window.desktop.print.silent === 'function') {
      window.desktop.print.silent({ deviceName: devName, widthMm: wMm, heightMm: Math.ceil(hMm), qty: 1, html: doc })
        .then(r => { if (!r || !r.ok) { console.warn('invoice print:', r && r.reason); browserPrintInvoice(body, css, hMm, wMm); } })
        .catch(() => browserPrintInvoice(body, css, hMm, wMm));
      return;
    }
    browserPrintInvoice(body, css, hMm, wMm);
  } catch (err) { console.error(err); toast('تعذّرت طباعة الفاتورة', 'r'); }
}

/* المحرر المرئي: ورقة بيضاء على سطح رمادي — سحب/تحجيم/تكبير بعجلة Ctrl — تراجع/إعادة — خطّا الجدول قابلان للسحب */
function renderDesignStudio(host) {
  let d = invDesign();
  let zoom = 1.35, selId = null, lastArrowT = 0;
  const undoStack = [], redoStack = [];
  const PX = 96 / 25.4; /* بكسل لكل ملم */
  const mmpx = v => (v * PX * zoom) + 'px';

  host.innerHTML = '';
  host.style.padding = '0';
  host.style.overflow = 'hidden';

  let persistT = null;
  const persist = () => {
    state.settings.invoiceDesign = d;
    DB.put('settings', state.settings);
    Sync.push('settings', state.settings);
  };
  const persistSoon = () => { clearTimeout(persistT); persistT = setTimeout(persist, 500); };
  const snap = () => JSON.stringify(d);
  const commit = () => { undoStack.push(snap()); if (undoStack.length > 50) undoStack.shift(); redoStack.length = 0; persistSoon(); };
  const undo = () => { if (!undoStack.length) return; redoStack.push(snap()); d = JSON.parse(undoStack.pop()); persistSoon(); drawAll(); };
  const redo = () => { if (!redoStack.length) return; undoStack.push(snap()); d = JSON.parse(redoStack.pop()); persistSoon(); drawAll(); };

  const newId = () => 'el' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const sel = () => d.elements.find(x => x.id === selId) || null;

  /* ── عنصر مرسوم داخل الورقة ── */
  function elNode(e) {
    const n = h('div', { class: 'ds-el' + (e.id === selId ? ' sel' : ''), dataset: { id: e.id } });
    n.style.right = mmpx(e.x); n.style.top = mmpx(e.y); n.style.width = mmpx(e.w); n.style.height = mmpx(e.h);
    if (e.t === 'img') {
      n.append(h('img', { src: e.src, draggable: false, style: { width: '100%', height: '100%', objectFit: 'contain', display: 'block', pointerEvents: 'none' } }));
    } else if (e.t === 'shape') {
      if (e.shape === 'hline') { n.style.height = '0'; n.style.borderTop = '1.5px solid ' + (e.stroke || '#111'); }
      else if (e.shape === 'vline') { n.style.width = '0'; n.style.borderRight = '1.5px solid ' + (e.stroke || '#111'); }
      else {
        n.style.border = '1.5px solid ' + (e.stroke || '#111');
        n.style.borderRadius = e.shape === 'ellipse' ? '50%' : (e.shape === 'rrect' ? mmpx(e.radius || 1.2) : '0');
        if (e.fill && e.fill !== 'none') n.style.background = e.fill;
      }
    } else {
      n.style.cssText += `font-family:'${e.font || 'Cairo'}',sans-serif;font-size:${((+e.size || 9) * 1.333 * zoom).toFixed(1)}px;font-weight:${e.bold ? 800 : 400};color:${e.color || '#111'};text-align:${e.align || 'center'};line-height:1.15;overflow:hidden;word-break:break-word;`;
      n.textContent = e.txt || '';
    }
    /* سحب العنصر (right-based: السحب يميناً يُنقص الإزاحة) */
    n.addEventListener('pointerdown', ev => {
      if (ev.target.classList.contains('rs')) return;
      ev.preventDefault(); ev.stopPropagation();
      if (selId !== e.id) { selId = e.id; drawAll(); }
      const node = pageEl.querySelector(`[data-id="${e.id}"]`);
      const x0 = ev.clientX, y0 = ev.clientY, sx = e.x, sy = e.y;
      let moved = false;
      const mv = e2 => {
        const dx = (e2.clientX - x0) / (PX * zoom), dy = (e2.clientY - y0) / (PX * zoom);
        if (!moved && Math.abs(dx) + Math.abs(dy) < 0.15) return;
        moved = true;
        e.x = Math.min(d.pageW - 1, Math.max(-1, sx - dx));
        e.y = Math.min(d.pageH - 1, Math.max(0, sy + dy));
        if (node) { node.style.right = mmpx(e.x); node.style.top = mmpx(e.y); }
      };
      const up = () => {
        document.removeEventListener('pointermove', mv); document.removeEventListener('pointerup', up);
        if (moved) { commit(); drawAll(); }
      };
      document.addEventListener('pointermove', mv); document.addEventListener('pointerup', up);
    });
    /* مقابض التحجيم الأربعة */
    [['nw', 'nwse-resize'], ['se', 'nwse-resize'], ['ne', 'nesw-resize'], ['sw', 'nesw-resize']].forEach(([corner, cur2]) => {
      const rs = h('span', { class: 'rs', style: {
        ...(corner.includes('n') ? { top: '-5px' } : { bottom: '-5px' }),
        ...(corner.includes('e') ? { right: '-5px' } : { left: '-5px' }), cursor: cur2 } });
      rs.addEventListener('pointerdown', ev => {
        ev.preventDefault(); ev.stopPropagation();
        const x0 = ev.clientX, y0 = ev.clientY, sx = e.x, sy = e.y, sw = e.w, sh = e.h;
        const isLineH = e.shape === 'hline', isLineV = e.shape === 'vline';
        const mv = e2 => {
          const dx = (e2.clientX - x0) / (PX * zoom), dy = (e2.clientY - y0) / (PX * zoom);
          const west = corner.includes('w'), north = corner.includes('n');
          if (!isLineV) {
            if (west) { e.w = Math.max(1, sw - dx); }
            else { const nx = Math.min(sx + sw - 1, Math.max(0, sx - dx)); e.w = sx + sw - nx; e.x = nx; }
          }
          if (!isLineH) {
            if (north) { e.y = Math.max(0, sy + dy); e.h = Math.max(1, sh - dy); }
            else e.h = Math.max(1, sh + dy);
          }
          const node = pageEl.querySelector(`[data-id="${e.id}"]`);
          if (node) { node.style.right = mmpx(e.x); node.style.top = mmpx(e.y); node.style.width = mmpx(e.w); node.style.height = mmpx(e.h); }
        };
        const up = () => { document.removeEventListener('pointermove', mv); document.removeEventListener('pointerup', up); commit(); drawAll(); };
        document.addEventListener('pointermove', mv); document.addEventListener('pointerup', up);
      });
      n.append(rs);
    });
    return n;
  }

  /* ── شريطا الأدوات ── */
  const bar1 = h('div', { class: 'ds-toolbar' });
  const bar2 = h('div', { class: 'ds-toolbar', style: { borderTop: '1px solid var(--line)' } });
  const mkBtn = (label, onclick, cls, title) => h('button', { class: 'ds-btn' + (cls ? ' ' + cls : ''), title: title || '', onclick }, label);
  const addEl = el => { commit(); d.elements.push(el); selId = el.id; drawAll(); };
  const addText = txt => addEl({ id: newId(), t: 'text', x: 6, y: 6, w: 68, h: 7, txt: txt || 'نص جديد', font: 'Cairo', size: 10, bold: false, color: '#111111', align: 'center' });
  const addShape = shape => addEl({ id: newId(), t: 'shape', shape, x: 10, y: 10, w: shape === 'vline' ? 0.4 : 40, h: shape === 'hline' ? 0.4 : 14, fill: 'none', stroke: '#111111', radius: 2 });
  const delSel = () => { if (!selId) return; commit(); d.elements = d.elements.filter(x => x.id !== selId); selId = null; drawAll(); };
  const dupSel = () => {
    const s = sel(); if (!s) return;
    commit();
    const cp = { ...JSON.parse(JSON.stringify(s)), id: newId(), x: s.x + 2, y: s.y + 2 };
    d.elements.push(cp); selId = cp.id; drawAll();
  };

  const imgInp = h('input', { type: 'file', accept: 'image/*,.svg', style: { display: 'none' } });
  imgInp.addEventListener('change', () => {
    const f = imgInp.files[0]; imgInp.value = '';
    if (!f) return;
    if (/svg/i.test(f.type) || /\.svg$/i.test(f.name)) {
      const r = new FileReader();
      r.onload = () => {
        let s = String(r.result || '');
        if (s.length > 400000) return toast('ملف SVG كبير جداً', 'r');
        s = s.replace(/<script[\s\S]*?(<\/script\s*>|$)/gi, '').replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '').replace(/javascript\s*:/gi, '');
        if (!/^\s*(<\?xml[^>]*>\s*)?<svg[\s>]/i.test(s)) return toast('ملف SVG غير صالح', 'r');
        addEl({ id: newId(), t: 'img', x: 25, y: 5, w: 30, h: 12, src: 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(s))) });
      };
      r.readAsText(f);
      return;
    }
    if (!/^image\/(png|jpe?g|webp|gif)$/i.test(f.type)) return toast('اختر صورة PNG/JPG/WebP أو ملف SVG', 'r');
    if (f.size > 3 * 1024 * 1024) return toast('الصورة كبيرة — الحد الأقصى 3MB', 'r');
    const r = new FileReader();
    r.onload = () => {
      const im = new Image();
      im.onload = () => {
        const k = Math.min(1, 400 / Math.max(im.width, im.height));
        const cv = document.createElement('canvas');
        cv.width = Math.max(1, Math.round(im.width * k)); cv.height = Math.max(1, Math.round(im.height * k));
        cv.getContext('2d').drawImage(im, 0, 0, cv.width, cv.height);
        const url = cv.toDataURL('image/png');
        if (url.length > 400000) return toast('الصورة كبيرة بعد الضغط — جرّب أصغر', 'r');
        addEl({ id: newId(), t: 'img', x: 25, y: 5, w: 30, h: Math.max(5, 30 * im.height / im.width), src: url });
      };
      im.onerror = () => toast('تعذّر فتح الصورة', 'r');
      im.src = r.result;
    };
    r.readAsDataURL(f);
  });

  const pageHInp = h('input', { class: 'ds-inp', type: 'number', min: 40, max: 400, value: d.pageH, title: 'ارتفاع الورقة بالملم — يتمدد تلقائياً مع عدد الأصناف' });
  pageHInp.addEventListener('change', () => {
    commit();
    d.pageH = Math.min(400, Math.max(40, num(pageHInp.value) || 92));
    if (d.tableTop > d.pageH - 10) d.tableTop = d.pageH - 10;
    if (d.tableBottom > d.pageH - 4) d.tableBottom = d.pageH - 4;
    drawAll();
  });
  const preview = () => {
    persist();
    const { body, css } = invBuildInvoice(invDemoSale());
    openModal({ title: 'معاينة الفاتورة (ببيانات تجريبية)', icon: 'eye', wide: true,
      body: h('div', { style: { display: 'flex', justifyContent: 'center', background: '#6b7686', borderRadius: '12px', padding: '18px' } },
        h('div', { html: `<style>${css}</style>${body}`, style: { boxShadow: '0 8px 30px rgba(0,0,0,.4)' } })) });
  };

  bar1.append(
    mkBtn('＋ نص', () => addText(), '', 'إضافة نص'),
    mkBtn('🖼 صورة / SVG', () => imgInp.click(), '', 'إضافة صورة أو شكل SVG والتحكم به مثل الورد'),
    mkBtn('▭ مستطيل', () => addShape('rect')),
    mkBtn('▢ مدوّر الحواف', () => addShape('rrect')),
    mkBtn('◯ دائرة', () => addShape('ellipse')),
    mkBtn('― خط أفقي', () => addShape('hline')),
    mkBtn('│ خط عمودي', () => addShape('vline')),
    h('span', { class: 'ds-sep' }),
    mkBtn('حذف', delSel, 'danger', 'حذف العنصر المحدد (Delete)'),
    mkBtn('تكرار', dupSel, '', 'Ctrl+D'),
    h('span', { class: 'ds-sep' }),
    mkBtn('↩ تراجع', undo, '', 'Ctrl+Z'),
    mkBtn('↪ إعادة', redo, '', 'Ctrl+Y'),
    h('span', { class: 'ds-sep' }),
    h('label', { style: { fontSize: '11.5px', fontWeight: 800, color: 'var(--muted)' } }, 'ارتفاع الورقة (مم):'), pageHInp,
    h('span', { class: 'ds-sep' }),
    mkBtn('استعادة الافتراضي', async () => {
      const yes = await confirmBox('استعادة التصميم الافتراضي؟ سيُفقد التصميم الحالي.', { danger: true, okLabel: 'استعادة' });
      if (!yes) return;
      commit(); d = invDefaultDesign(); selId = null; drawAll(); persist();
      toast('استُعيد التصميم الافتراضي', 'b');
    }, 'danger'),
    h('span', { style: { flex: 1 } }),
    mkBtn('حفظ التصميم', () => { persist(); toast('حُفظ تصميم الفاتورة ويُزامَن مع الأجهزة'); }, 'primary'),
    mkBtn('معاينة', preview),
    mkBtn('طباعة تجريبية', () => { persist(); printSaleInvoice(invDemoSale()); }));

  /* خصائص العنصر المحدد */
  const fontSel = h('select', { class: 'ds-sel' }, INV_FONTS.map(f => h('option', { value: f }, f)));
  const sizeInp = h('input', { class: 'ds-inp', type: 'number', min: 5, max: 40, step: 0.5, title: 'حجم الخط (pt)' });
  const boldBtn = mkBtn('B', () => { const s = sel(); if (!s) return; commit(); s.bold = !s.bold; drawAll(); }, '', 'عريض');
  const colorInp = h('input', { class: 'ds-color', type: 'color', title: 'لون النص' });
  const alignSel = h('select', { class: 'ds-sel' }, h('option', { value: 'right' }, 'يمين'), h('option', { value: 'center' }, 'وسط'), h('option', { value: 'left' }, 'يسار'));
  const fillInp = h('input', { class: 'ds-color', type: 'color', title: 'لون التعبئة' });
  const fillNoneBtn = mkBtn('بلا تعبئة', () => { const s = sel(); if (!s) return; commit(); s.fill = 'none'; drawAll(); });
  const strokeInp = h('input', { class: 'ds-color', type: 'color', title: 'لون الحدود' });
  const radiusInp = h('input', { class: 'ds-inp', type: 'number', min: 0, max: 20, step: 0.5, title: 'نصف قطر التدوير (مم)' });
  const wInp = h('input', { class: 'ds-inp', type: 'number', min: 1, max: 120, step: 0.5, title: 'العرض (مم)' });
  const hInp = h('input', { class: 'ds-inp', type: 'number', min: 1, max: 400, step: 0.5, title: 'الارتفاع (مم)' });
  const txtInp = h('input', { class: 'ds-sel', style: { minWidth: '180px' }, placeholder: 'محتوى النص…' });
  const bind = (inp, fn) => inp.addEventListener('change', () => { const s = sel(); if (!s) return; commit(); fn(s); drawAll(); });
  bind(fontSel, s => s.font = fontSel.value);
  bind(sizeInp, s => s.size = Math.min(40, Math.max(5, num(sizeInp.value) || 9)));
  bind(colorInp, s => s.color = colorInp.value);
  bind(alignSel, s => s.align = alignSel.value);
  bind(fillInp, s => s.fill = fillInp.value);
  bind(strokeInp, s => s.stroke = strokeInp.value);
  bind(radiusInp, s => s.radius = Math.max(0, num(radiusInp.value)));
  bind(wInp, s => s.w = Math.max(1, num(wInp.value) || s.w));
  bind(hInp, s => s.h = Math.max(1, num(hInp.value) || s.h));
  txtInp.addEventListener('input', () => { const s = sel(); if (!s || s.t !== 'text') return; s.txt = txtInp.value; persistSoon(); const node = pageEl.querySelector(`[data-id="${s.id}"]`); if (node) node.textContent = s.txt; });
  txtInp.addEventListener('change', () => { commit(); drawAll(); });

  bar2.append(
    h('label', { style: { fontSize: '11.5px', fontWeight: 800, color: 'var(--muted)' } }, 'متغيرات الفاتورة:'),
    ...INV_VARS.map(([k, label]) => h('button', { class: 'ds-var', title: 'إضافة متغير «' + label + '» كنص قابل للسحب', onclick: () => addText('{{' + k + '}}') }, label)),
    h('span', { class: 'ds-sep' }),
    fontSel, sizeInp, boldBtn, colorInp, alignSel, txtInp,
    h('span', { class: 'ds-sep' }),
    h('label', { style: { fontSize: '11.5px', fontWeight: 800, color: 'var(--muted)' } }, 'تعبئة:'), fillInp, fillNoneBtn,
    h('label', { style: { fontSize: '11.5px', fontWeight: 800, color: 'var(--muted)' } }, 'حدود:'), strokeInp,
    h('label', { style: { fontSize: '11.5px', fontWeight: 800, color: 'var(--muted)' } }, 'تدوير:'), radiusInp,
    h('label', { style: { fontSize: '11.5px', fontWeight: 800, color: 'var(--muted)' } }, 'ع×ا:'), wInp, hInp);

  const stage = h('div', { class: 'ds-stage' });
  const pageEl = h('div', { class: 'ds-page' });
  stage.append(pageEl);
  const status = h('div', { class: 'ds-status' });
  host.append(bar1, bar2, stage, status, imgInp);

  function updateProps() {
    const s = sel();
    [fontSel, sizeInp, boldBtn, colorInp, alignSel, fillInp, fillNoneBtn, strokeInp, radiusInp, wInp, hInp, txtInp].forEach(x => x.disabled = !s);
    if (!s) { txtInp.value = ''; return; }
    fontSel.value = s.font || 'Cairo';
    sizeInp.value = s.size || 9;
    colorInp.value = s.color || '#111111';
    alignSel.value = s.align || 'center';
    fillInp.value = s.fill && s.fill !== 'none' ? s.fill : '#ffffff';
    strokeInp.value = s.stroke || '#111111';
    radiusInp.value = s.radius || 0;
    wInp.value = Math.round((s.w || 0) * 10) / 10;
    hInp.value = Math.round((s.h || 0) * 10) / 10;
    txtInp.value = s.t === 'text' ? (s.txt || '') : '';
    txtInp.style.display = s.t === 'text' ? '' : 'none';
    fontSel.style.display = sizeInp.style.display = boldBtn.style.display = colorInp.style.display = alignSel.style.display = s.t === 'text' ? '' : 'none';
    fillInp.style.display = fillNoneBtn.style.display = radiusInp.style.display = s.t === 'shape' && s.shape !== 'hline' && s.shape !== 'vline' ? '' : 'none';
    radiusInp.style.display = s.t === 'shape' && s.shape === 'rrect' ? '' : 'none';
    strokeInp.style.display = s.t === 'shape' ? '' : 'none';
  }

  function drawAll() {
    pageEl.innerHTML = '';
    pageEl.style.width = (d.pageW * PX * zoom) + 'px';
    pageEl.style.height = (d.pageH * PX * zoom) + 'px';
    pageEl.append(h('div', { class: 'ds-band', style: { top: (d.tableTop * PX * zoom) + 'px', height: ((d.tableBottom - d.tableTop) * PX * zoom) + 'px' } }));
    d.elements.forEach(e => pageEl.append(elNode(e)));
    [['tableTop', 'بداية جدول الأصناف — اسحبني'], ['tableBottom', 'نهاية الجدول — اسحبني']].forEach(([k, label]) => {
      const mk = h('div', { class: 'ds-marker', style: { top: (d[k] * PX * zoom) + 'px' } }, h('span', {}, label));
      mk.addEventListener('pointerdown', ev => {
        ev.preventDefault(); ev.stopPropagation();
        const y0 = ev.clientY, v0 = d[k];
        const band = pageEl.querySelector('.ds-band');
        const mv = e2 => {
          d[k] = Math.min(d.pageH - 4, Math.max(4, v0 + (e2.clientY - y0) / (PX * zoom)));
          if (d.tableBottom <= d.tableTop + 5) { if (k === 'tableTop') d.tableBottom = d.tableTop + 5; else d.tableTop = d.tableBottom - 5; }
          mk.style.top = (d[k] * PX * zoom) + 'px';
          if (band) { band.style.top = (d.tableTop * PX * zoom) + 'px'; band.style.height = ((d.tableBottom - d.tableTop) * PX * zoom) + 'px'; }
        };
        const up = () => { document.removeEventListener('pointermove', mv); document.removeEventListener('pointerup', up); commit(); drawAll(); };
        document.addEventListener('pointermove', mv); document.addEventListener('pointerup', up);
      });
      pageEl.append(mk);
    });
    updateProps();
    status.textContent = `الورقة ${d.pageW}×${d.pageH}مم • ${d.elements.length} عنصر • التكبير ${Math.round(zoom * 100)}% — Ctrl+عجلة الماوس: تكبير/تصغير • Ctrl+Z تراجع • Ctrl+Y إعادة • Ctrl+D تكرار • Delete حذف • الأسهم تحريك (Shift أسرع)`;
  }

  /* Ctrl + عجلة الماوس = تكبير/تصغير */
  stage.addEventListener('wheel', e => {
    if (!e.ctrlKey) return;
    e.preventDefault();
    zoom = Math.min(3, Math.max(0.5, zoom * (e.deltaY < 0 ? 1.12 : 0.89)));
    drawAll();
  }, { passive: false });
  /* نقرة على الخلفية تلغي التحديد */
  stage.addEventListener('pointerdown', e => { if (e.target === stage) { selId = null; drawAll(); } });
  /* اختصارات لوحة المفاتيح — تتوقف تلقائياً عند مغادرة الاستوديو */
  const onKey = e => {
    if (!host.isConnected) { document.removeEventListener('keydown', onKey); return; }
    if ($('#modal-root').children.length) return;
    const ae = document.activeElement;
    if (ae && (/^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName) || ae.isContentEditable)) return;
    if (e.ctrlKey && !e.shiftKey && (e.key === 'z' || e.key === 'Z')) { e.preventDefault(); undo(); return; }
    if (e.ctrlKey && (e.key === 'y' || e.key === 'Y' || (e.shiftKey && (e.key === 'z' || e.key === 'Z')))) { e.preventDefault(); redo(); return; }
    if (e.ctrlKey && (e.key === 'd' || e.key === 'D')) { e.preventDefault(); dupSel(); return; }
    const s = sel(); if (!s) return;
    if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); delSel(); return; }
    if (e.key === 'Escape') { selId = null; drawAll(); return; }
    if (e.key.startsWith('Arrow')) {
      e.preventDefault();
      const now = Date.now();
      if (now - lastArrowT > 700) { undoStack.push(snap()); if (undoStack.length > 50) undoStack.shift(); redoStack.length = 0; }
      lastArrowT = now;
      const step = e.shiftKey ? 2 : 0.5;
      if (e.key === 'ArrowUp') s.y = Math.max(0, s.y - step);
      if (e.key === 'ArrowDown') s.y = Math.min(d.pageH, s.y + step);
      if (e.key === 'ArrowLeft') s.x = Math.min(d.pageW, s.x + step);   /* right-based: يسار يزيد الإزاحة */
      if (e.key === 'ArrowRight') s.x = Math.max(0, s.x - step);
      drawAll(); persistSoon();
    }
  };
  document.addEventListener('keydown', onKey);
  drawAll();
}

/* ───────────────────────── 24) تبويب الماسح الذكي ───────────────────────── */
function renderScannerTab(tab) {
  const page = h('div', { class: 'page', style: { overflowY: 'auto' } });
  page.append(h('div', { class: 'page-head' }, h('div', { class: 'page-title' }, h('span', { html: icon('camera') }), 'قراءة الفواتير الورقية بالصور')));
  const mount = h('div', { class: 'page-body', style: { padding: '18px', overflowY: 'auto' } });
  page.append(mount);
  tab.el.append(page);
  InvoiceScanner.mount(mount, {
    getKey: () => state.settings.geminiKey,
    onImport: items => {
      const rt = tab.props.returnTab && tabs.find(t => t.id === tab.props.returnTab);
      const target = (rt && rt.type === 'purchase') ? rt : openTab('purchase');
      let added = 0, missed = 0;
      items.forEach(it => {
        const p = (it.productId && findProd(it.productId)) ||
          state.products.find(x => !x.deleted && x.brandName.trim().toLowerCase() === String(it.name || '').trim().toLowerCase());
        if (!p) { missed++; return; }
        addPurchaseItem(target, p, +it.qty || 1, {
          price: it.price ?? it.unitPrice ?? it.buyPrice ?? it.cost,
          expiry: (InvoiceScanner.normExpiry && InvoiceScanner.normExpiry(it.expiry)) || '',
          silent: true,
        });
        added++;
      });
      activateTab(target.id);
      toast(`استُوردت ${added} مادة إلى قائمة الشراء` + (missed ? ` — ${missed} غير موجودة في المخزن` : ''), missed ? 'r' : 'g');
    },
  });
}

/* ───────────────────────── 24-أ) إرجاع بيع (واجهة نقطة البيع + لوح ذكي) ───────────────────────── */
function renderReturnSale(tab) {
  const st = tab.state;
  st.cart = st.cart || [];
  st.discount = st.discount || 0;
  const wrap = h('div', { class: 'pos-layout' });
  const center = h('div', { class: 'pos-center' });

  /* محرك البحث */
  const sInput = h('input', { placeholder: 'ابحث عن الصنف المُرجَع أو امسح باركوده…', autocomplete: 'off' });
  const sugBox = h('div', { class: 'suggestions' });
  st.searchInput = sInput;
  sInput.addEventListener('input', () => {
    const q = sInput.value;
    const sugItems = searchProducts(q);
    sugBox.innerHTML = '';
    if (!q.trim()) { sugBox.classList.remove('show'); return; }
    if (!sugItems.length) sugBox.append(h('div', { class: 'sug-empty' }, `لا نتائج لـ «${q}»`));
    else sugItems.forEach(p => sugBox.append(h('div', { class: 'sug-item', onclick: () => pick(p) },
      h('span', { class: 'sug-ic', html: icon('pill') }),
      h('div', { class: 'sug-name' }, p.brandName, coTag(p),h('small', {}, `${p.scientificName || ''}${p.scientificName ? ' • ' : ''}${p.form || ''} ${p.dose || ''}`)),
      h('span', { class: 'sug-price' }, `${fmt(salePerUnit(p, p.units.length - 1))} ${cur()}`))));
    sugBox.classList.add('show');
  });
  sInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const sugItems = searchProducts(sInput.value);
      if (sugItems.length) pick(sugItems[0]);
      else if (sInput.value.trim()) toast('لا يوجد صنف مطابق', 'r');
    } else if (e.key === 'Escape') sugBox.classList.remove('show');
  });
  document.addEventListener('mousedown', e => { if (!sugBox.contains(e.target) && e.target !== sInput) sugBox.classList.remove('show'); });
  function pick(p) { addRetItem(tab, p); sInput.value = ''; sugBox.classList.remove('show'); sInput.focus(); }
  center.append(h('div', { class: 'search-engine' },
    h('div', { class: 'search-box' }, h('span', { html: icon('search') }), sInput,
      h('span', { class: 'search-hint' }, 'المُرجَع يعود للمخزون تلقائياً')), sugBox));

  /* سلة الإرجاع */
  const cartWrap = h('div', { class: 'cart-wrap' });
  st.renderCart = () => {
    cartWrap.innerHTML = '';
    if (!st.cart.length) {
      cartWrap.append(h('div', { class: 'cart-empty' }, h('span', { html: icon('refresh') }),
        h('p', {}, 'سلة الإرجاع فارغة — أدخل الأصناف المُرجعة من الزبون')));
      return;
    }
    const tbody = h('tbody');
    st.cart.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', { class: it.productId === st.activeProductId ? 'row-focus' : '' },
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name', style: { cursor: 'pointer' }, title: 'اضغط لعرض سجل بيع هذا الصنف في اللوح الجانبي',
          onclick: () => { st.activeProductId = it.productId; st.renderCart(); st.drawSide(); } },
          it.name,coTag(p), h('small', {}, p ? `${p.form || ''} ${p.dose || ''}` : '')),
        h('td', {}, (() => {
          const sel = h('select', { class: 'unit-select' }, (p ? p.units : [{ name: it.unitName }]).map((u, ui) => h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => {
            it.unitIdx = +sel.value;
            if (p) { it.sale = salePerUnit(p, it.unitIdx); it.cost = costPerUnit(p, it.unitIdx); }
            st.renderCart(); st.renderTotals();
          });
          return sel;
        })()),
        h('td', {}, (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 0.5, step: 'any' });
          q.addEventListener('change', () => { it.qty = Math.max(0.5, num(q.value) || 1); st.renderCart(); st.renderTotals(); });
          return h('div', { class: 'qty-ctl' },
            h('button', { onclick: () => { it.qty++; st.renderCart(); st.renderTotals(); } }, '+'), q,
            h('button', { onclick: () => { if (it.qty > 1) { it.qty--; st.renderCart(); st.renderTotals(); } } }, '−'));
        })()),
        h('td', { class: 'td-num td-sale' }, fmt(it.sale)),
        h('td', { class: 'td-num td-total' }, fmt(it.sale * it.qty)),
        h('td', {}, h('div', { class: 'row-act' },
          h('button', { class: 'icon-btn view', title: 'تفاصيل المنتج', html: icon('eye'), onclick: () => openTab('details', { productId: it.productId }) }),
          h('button', { class: 'icon-btn del', title: 'حذف من السلة', html: icon('trash'), onclick: () => { st.cart.splice(i, 1); st.renderCart(); st.renderTotals(); } }))),
      ));
    });
    cartWrap.append(h('div', { class: 'tbl-scroll' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'اسم المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'),
          h('th', {}, 'سعر البيع'), h('th', {}, 'المجموع'), h('th', {}, 'إجراء'))),
        tbody)));
  };

  /* الإجماليات + زر الإرجاع الوحيد */
  const subEl = h('div', { class: 'tval' }, '0');
  const grandEl = h('div', { class: 'tval' }, h('span', {}, '0'), ' ', h('small', {}, cur()));
  const discInp = h('input', { type: 'number', min: 0, placeholder: '0', value: st.discount || '' });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); st.renderTotals(); });
  st.renderTotals = () => {
    const sub = st.cart.reduce((s, it) => s + it.sale * it.qty, 0);
    animNum(subEl, sub);
    animNum(grandEl.firstChild, Math.max(0, sub - st.discount));
  };
  const footer = h('div', { class: 'pos-footer' },
    h('div', { class: 'totals-row' },
      h('div', { class: 'total-card' }, h('label', {}, 'مجموع المسترجع'), subEl),
      h('div', { class: 'total-card' }, h('label', {}, 'الخصم'), h('div', { class: 'discount-wrap' }, discInp)),
      h('div', { class: 'total-card grand red-grand' }, h('label', {}, 'المبلغ المسترجع للزبون'), grandEl)),
    h('div', { class: 'pay-row' },
      h('button', { class: 'pay-btn credit', onclick: () => finalizeReturnSale(tab) },
        h('span', { html: icon('refresh') }), 'إرجاع البيع')));

  /* اللوح الذكي (25%): آخر 5 فواتير بيع لآخر صنف أُدخل — ويتبدل تلقائياً مع كل صنف جديد */
  const side = h('div', { class: 'pos-side' });
  side.append(h('div', { class: 'side-tabs' }, h('div', { class: 'side-tab active' }, 'سجل بيع الصنف')));
  const sideBody = h('div', { class: 'side-body' });
  st.drawSide = () => {
    sideBody.innerHTML = '';
    const pid = st.activeProductId;
    if (!pid) { sideBody.append(h('div', { class: 'empty-note' }, 'أدخل أي صنف لسلة الإرجاع', h('br'), 'وستظهر هنا آخر 5 قوائم بيع له')); return; }
    const p = findProd(pid);
    sideBody.append(h('div', { class: 'inv-mini', style: { cursor: 'default', borderColor: 'var(--green-soft)', background: 'var(--green-ghost)' } },
      h('div', { class: 'im-top' }, h('span', {}, p ? p.brandName : '—'), h('span', { class: 'badge g' }, 'آخر 5 مبيعات'))));
    const sales = state.sales.filter(s => s.type === 'sale' && (s.items || []).some(x => x.productId === pid)).sort((a, b) => b.ts - a.ts).slice(0, 5);
    if (!sales.length) { sideBody.append(h('div', { class: 'empty-note' }, 'لم يُبع هذا الصنف سابقاً')); return; }
    sales.forEach(s => {
      const itm = s.items.find(x => x.productId === pid);
      sideBody.append(h('div', { class: 'inv-mini', style: { cursor: 'default' } },
        h('div', { class: 'im-top' }, h('span', {}, `${fmtDate(s.ts)} • ${fmtTime(s.ts)}`), h('b', {}, `${fmt(itm.qty)} ${itm.unitName || ''}`)),
        h('div', { class: 'im-sub' }, h('span', {}, `${s.employeeName} • ${s.customerName || 'زبون نقدي'}`), h('span', { class: 'badge g' }, `${fmt(itm.total)} ${cur()}`)),
        h('div', { class: 'side-actions', style: { margin: '8px 0 0' } },
          h('button', { class: 'mini-btn blue', onclick: () => viewSaleModal(s) }, h('span', { html: icon('eye') }), 'عرض'),
                    h('button', { class: 'mini-btn green', onclick: () => openTab('editsale', { saleId: s.id }) }, h('span', { html: icon('edit') }), 'تعديل'))));
    });
  };
  side.append(sideBody);

  center.append(cartWrap);
  wrap.append(h('div', { style: { flex: 1, display: 'flex', minHeight: 0 } }, center, side), footer);
  tab.el.append(wrap);
  st.renderCart(); st.renderTotals(); st.drawSide();
  setTimeout(() => sInput.focus(), 60);
}
function addRetItem(tab, p) {
  const st = tab.state;
  const ex = st.cart.find(it => it.productId === p.id && it.unitIdx === p.units.length - 1);
  if (ex) ex.qty++;
  else st.cart.push({ productId: p.id, name: p.brandName, unitIdx: p.units.length - 1, qty: 1,
    cost: costPerUnit(p, p.units.length - 1), sale: salePerUnit(p, p.units.length - 1) });
  st.activeProductId = p.id; // اللوح الذكي يتبع آخر صنف مُدخل
  st.renderCart(); st.renderTotals(); st.drawSide();
}
async function finalizeReturnSale(tab) {
  const st = tab.state;
  if (st.processing) return;
  if (!st.cart.length) return toast('سلة الإرجاع فارغة', 'r');
  const yes = await confirmBox('تأكيد إرجاع البيع؟ ستعود الأصناف إلى المخزون وتُسجَّل العملية في تقرير المبيعات كاسترجاع بيع.', { okLabel: 'إرجاع البيع', icon: 'refresh', danger: true });
  if (!yes) return;
  st.processing = true;
  const acc = me();
  const items = st.cart.map(it => {
    const p = findProd(it.productId);
    return { ...it, unitName: p ? p.units[it.unitIdx].name : it.unitName || '', qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.sale * it.qty };
  });
  const subtotal = items.reduce((s, it) => s + it.total, 0);
  const cost = items.reduce((s, it) => s + it.cost * it.qty, 0);
  const net = Math.max(0, subtotal - st.discount);
  const ts = Date.now();
  const ret = {
    id: uid(), type: 'return', version: 1, versions: [],
    items, subtotal, discount: st.discount, net, cost, profit: -(net - cost),
    pay: 'cash', customerId: state.customerId, customerName: state.customerId ? (findCust(state.customerId) || {}).name : 'زبون نقدي',
    employeeId: acc.id, employeeName: acc.name,
    ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
  };
  await save('sales', ret);
  for (const it of items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) + it.qtyBase; await save('products', p); } }
  st.cart = []; st.discount = 0; st.activeProductId = null; st.processing = false;
  renderTabContent(tab); renderSideNav();
  toast(`تم إرجاع البيع — ${fmt(net)} ${cur()} وعادت الأصناف للمخزون`, 'b');
}

/* ───────────────────────── 24-ب) إرجاع شراء ───────────────────────── */
function renderReturnPurchase(tab) {
  const st = tab.state;
  st.items = st.items || [];
  const page = h('div', { class: 'pos-layout' });
  const center = h('div', { class: 'pos-center' });

  const supSel = h('select', {}, h('option', { value: '' }, '— اختر المذخر —'),
    state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: st.supplierId === s.id }, s.name)));
  const debtEl = h('b', { style: { color: 'var(--red)', fontSize: '15px' } }, '—');
  const drawDebt = () => { const s = findSup(st.supplierId); if (s) animNum(debtEl, s.debt || 0, ' ' + cur()); else debtEl.textContent = '—'; };
  supSel.addEventListener('change', () => { st.supplierId = supSel.value || null; drawDebt(); });
  drawDebt();
  center.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'المذخر'), supSel),
    h('div', { class: 'f-group' }, h('label', {}, 'الدين الحالي'), debtEl),
    h('div', { class: 'spacer' })));

  const sInput = h('input', { placeholder: 'أدخل باركود الصنف المُرجَع أو ابحث بالاسم…', autocomplete: 'off' });
  const sugBox = h('div', { class: 'suggestions' });
  sInput.addEventListener('input', () => {
    const q = sInput.value;
    const sugItems = searchProducts(q);
    sugBox.innerHTML = '';
    if (!q.trim()) { sugBox.classList.remove('show'); return; }
    if (!sugItems.length) sugBox.append(h('div', { class: 'sug-empty' }, 'غير موجود في المخزن'));
    else sugItems.forEach(p => sugBox.append(h('div', { class: 'sug-item', onclick: () => pick(p) },
      h('span', { class: 'sug-ic', html: icon('pill') }),
      h('div', { class: 'sug-name' }, p.brandName,coTag(p), h('small', {}, `${p.form || ''} ${p.dose || ''}`)),
      h('span', { class: 'sug-price' }, `شراء ${fmt(costPerUnit(p, 0))} / ${bigUnitName(p)}`))));
    sugBox.classList.add('show');
  });
  sInput.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    const sugItems = searchProducts(sInput.value);
    if (sugItems.length) pick(sugItems[0]);
  });
  function pick(p) { addRetPurchItem(tab, p); sInput.value = ''; sugBox.classList.remove('show'); sInput.focus(); }
  center.append(h('div', { class: 'search-engine' },
    h('div', { class: 'search-box' }, h('span', { html: icon('barcode') }), sInput,
      h('span', { class: 'search-hint' }, 'الإرجاع يُنقص المخزون')), sugBox));

  const cartWrap = h('div', { class: 'cart-wrap' });
  st.renderItems = () => {
    cartWrap.innerHTML = '';
    if (!st.items.length) {
      cartWrap.append(h('div', { class: 'cart-empty' }, h('span', { html: icon('purchase') }), h('p', {}, 'أدخل الأصناف المُرجعة للمذخر')));
      return;
    }
    const tbody = h('tbody');
    st.items.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, it.name, h('small', {}, p ? `${p.form || ''} ${p.dose || ''}` : '')),
        h('td', {}, p ? (() => {
          const sel = h('select', { class: 'unit-select' }, p.units.map((u, ui) => h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => { it.unitIdx = +sel.value; it.buyPrice = Math.round(costPerUnit(p, it.unitIdx) * 100) / 100; st.renderItems(); drawTotals(); });
          return sel;
        })() : (it.unitName || '')),
        h('td', {}, (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 1, style: { width: '70px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          q.addEventListener('change', () => { it.qty = Math.max(1, num(q.value) || 1); drawTotals(); });
          return q;
        })()),
        h('td', {}, (() => {
          const pr = h('input', { type: 'number', value: it.buyPrice, min: 0, style: { width: '90px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          pr.addEventListener('change', () => { it.buyPrice = num(pr.value); drawTotals(); });
          return pr;
        })()),
        h('td', { class: 'td-num td-total' }, fmt(it.buyPrice * it.qty)),
        h('td', {}, h('button', { class: 'icon-btn del', html: icon('trash'), onclick: () => { st.items.splice(i, 1); st.renderItems(); drawTotals(); } })),
      ));
    });
    cartWrap.append(h('div', { class: 'tbl-scroll' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'سعر الشراء'), h('th', {}, 'المجموع'), h('th', {}, 'حذف'))),
        tbody)));
  };

  const totalEl = h('div', { class: 'tval' }, h('span', {}, '0'), ' ', h('small', {}, cur()));
  function drawTotals() { animNum(totalEl.firstChild, st.items.reduce((s, it) => s + it.buyPrice * it.qty, 0)); }
  const footer = h('div', { class: 'pos-footer' },
    h('div', { class: 'totals-row' },
      h('div', { class: 'total-card grand red-grand' }, h('label', {}, 'إجمالي المُرجَع للمذخر'), totalEl)),
    h('div', { class: 'pay-row' },
      h('button', { class: 'pay-btn credit', onclick: () => saveReturnPurchaseModal(tab) }, h('span', { html: icon('refresh') }), 'حفظ إرجاع الشراء')));

  center.append(cartWrap);
  const side = h('div', { class: 'pos-side' });
  side.append(h('div', { class: 'side-tabs' }, h('div', { class: 'side-tab active' }, 'استرجاعات الشراء السابقة')));
  const sideBody = h('div', { class: 'side-body' });
    state.purchases.filter(p => p.type === 'purchase' && !p.deleted).sort((a, b) => b.ts - a.ts).slice(0, 30).forEach(pu =>
    sideBody.append(h('div', { class: 'inv-mini', onclick: () => openTab('editpurch', { purchaseId: pu.id, readonly: true }) },
      h('div', { class: 'im-top' }, h('span', {}, pu.supplierName), h('b', {}, `${fmt(pu.total)} ${cur()}`)),
      h('div', { class: 'im-sub' }, h('span', {}, `${fmtDate(pu.ts)} ${fmtTime(pu.ts)}`),
        h('span', { class: 'badge ' + (pu.pay === 'cash' ? 'g' : 'r') }, pu.pay === 'cash' ? 'كاش مسترد' : 'أُنقص من الدين')))));
  if (!sideBody.children.length) sideBody.append(h('div', { class: 'empty-note' }, 'لا استرجاعات سابقة'));
  side.append(sideBody);
  page.append(h('div', { style: { flex: 1, display: 'flex', minHeight: 0 } }, center, side), footer);
  tab.el.append(page);
  st.renderItems(); drawTotals();
  setTimeout(() => sInput.focus(), 60);
}
function addRetPurchItem(tab, p) {
  const st = tab.state;
  st.items = st.items || [];
  const ex = st.items.find(it => it.productId === p.id && it.unitIdx === 0);
  if (ex) ex.qty += 1;
  else st.items.push({ productId: p.id, name: p.brandName, unitIdx: 0, qty: 1, buyPrice: costPerUnit(p, 0) });
  if (st.renderItems) st.renderItems();
}
async function saveReturnPurchaseModal(tab) {
  const st = tab.state;
  if (!st.items.length) return toast('القائمة فارغة', 'r');
  if (!st.supplierId) return toast('اختر المذخر أولاً', 'r');
  const sup = findSup(st.supplierId);
  const total = st.items.reduce((s, it) => s + it.buyPrice * it.qty, 0);
  openModal({
    title: 'تسوية إرجاع الشراء', icon: 'refresh',
    body: h('div', {},
      h('div', { class: 'sum-card r', style: { marginBottom: '10px' } }, h('label', {}, `قيمة الأصناف المُرجعة للمذخر «${sup.name}»`), h('b', {}, animSpan(total, ' ' + cur()))),
      h('div', { class: 'sum-card n' }, h('label', {}, 'الدين الحالي قبل الإرجاع'), h('b', {}, animSpan(sup.debt || 0, ' ' + cur())))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'آجل (يُنقص الدين)', cls: 'r', icon: 'clock', big: true, onClick: c => { c(); finalizeReturnPurchase(tab, 'credit'); } },
      { label: 'كاش (مبلغ مسترد)', cls: 'g', icon: 'cash', big: true, onClick: c => { c(); finalizeReturnPurchase(tab, 'cash'); } },
    ],
  });
}
async function finalizeReturnPurchase(tab, pay) {
  const st = tab.state;
  const sup = findSup(st.supplierId);
  const acc = me();
  const ts = Date.now();
  const items = st.items.map(it => {
    const p = findProd(it.productId);
    return { ...it, unitName: p ? p.units[it.unitIdx].name : '', qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.buyPrice * it.qty };
  });
  const total = items.reduce((s, it) => s + it.total, 0);
  const pu = {
    id: uid(), type: 'return', version: 1, versions: [],
    supplierId: sup.id, supplierName: sup.name, listNum: state.purchases.length + 1,
    items, discount: 0, total, pay, debtAfter: sup.debt || 0,
    employeeId: acc.id, employeeName: acc.name,
    ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
  };
  await save('purchases', pu);
  for (const it of items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) - it.qtyBase; await save('products', p); } }
  await recomputeSupplierDebt(sup.id); // يُنقص الدين إذا كان الإرجاع آجلاً + يعيد حساب debtAfter لكل السجل
  st.items = []; st.supplierId = null;
  renderTabContent(tab); renderSideNav();
  toast(`حُفظ إرجاع الشراء — ${fmt(total)} ${cur()} ${pay === 'credit' ? '(أُنقص من دين المذخر)' : '(مبلغ مسترد نقداً)'}`, 'b');
}

/* ───────────────────────── 24-ج) كشف حساب مذخر ───────────────────────── */
function renderStatement(tab) {
  const st = tab.state;
  st.f = st.f || { supplier: '', from: '', to: '' };
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' }, h('div', { class: 'page-title' }, h('span', { html: icon('receipt') }), 'كشف حساب مذخر')));
  const supSel = h('select', {}, h('option', { value: '' }, '— اختر المذخر —'),
    state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: st.f.supplier === s.id }, s.name)));
  supSel.addEventListener('change', () => { st.f.supplier = supSel.value; draw(); });
  const fromI = h('input', { type: 'date', value: st.f.from }), toI = h('input', { type: 'date', value: st.f.to });
  fromI.addEventListener('change', () => { st.f.from = fromI.value; draw(); });
  toI.addEventListener('change', () => { st.f.to = toI.value; draw(); });
  page.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'المذخر'), supSel),
    h('div', { class: 'f-group' }, h('label', {}, 'من'), fromI, h('label', {}, 'إلى'), toI)));
  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });
  page.append(bodyBox, footBox);

    function allEvents() { /* كل حركات المذخر مرتبة تصاعدياً لحساب الرصيد المتراكم الصحيح */
    if (!st.f.supplier) return [];
    const evs = [];
    const sup0 = findSup(st.f.supplier);
    if (sup0 && sup0.openingDebt) evs.push({ kind: 'opening', ts: sup0.createdAt || 0,
      doc: { supplierName: sup0.name, amount: sup0.openingDebt, ts: sup0.createdAt || Date.now(), date: dateStr(sup0.createdAt || Date.now()), time: timeStr(sup0.createdAt || Date.now()) } });
    state.purchases.filter(p => p.supplierId === st.f.supplier && !p.deleted)
      .forEach(p => evs.push({ kind: p.type === 'purchase' ? 'buy' : 'buyret', doc: p, ts: p.ts }));
    state.payments.filter(p => p.supplierId === st.f.supplier && !p.deleted)
      .forEach(p => evs.push({ kind: p.kind === 'deposit' ? 'deposit' : 'pay', doc: p, ts: p.ts }));
    evs.sort((a, b) => a.ts - b.ts);
    let run = 0;
    evs.forEach(e => {
      const d = e.doc;
      if (e.kind === 'opening') run += d.amount;
      else if (e.kind === 'buy') run += d.pay === 'credit' ? d.total : 0;
      else if (e.kind === 'buyret') run -= d.pay === 'credit' ? d.total : 0;
      else if (e.kind === 'pay') run -= d.amount + (d.discount || 0);
      else run -= d.amount;
      e.after = run; // الرصيد المتراكم بعد العملية مباشرة
    });
    return evs;
  }
  function draw() {
    bodyBox.innerHTML = ''; footBox.innerHTML = '';
    if (!st.f.supplier) { bodyBox.append(h('div', { class: 'empty-note' }, 'اختر مذخراً من الأعلى لعرض كشف حسابه الكامل')); return; }
    const sup = findSup(st.f.supplier);
    const evs = allEvents().filter(e => {
      const d = e.doc;
      return (!st.f.from || d.date >= st.f.from) && (!st.f.to || d.date <= st.f.to);
    });
    const tbody = h('tbody');
    [...evs].reverse().forEach(e => { /* العرض: الأحدث أولاً */
      const d = e.doc;
            const isDoc = e.kind === 'buy' || e.kind === 'buyret';
      const label = e.kind === 'opening' ? 'رصيد افتتاحي' : e.kind === 'buy' ? 'شراء' : e.kind === 'buyret' ? 'استرجاع شراء' : e.kind === 'pay' ? 'تسديد' : 'إيداع';
      const badgeCls = e.kind === 'opening' ? 'n' : e.kind === 'buy' ? 'b' : e.kind === 'buyret' ? 'r' : e.kind === 'pay' ? 'g' : 'n';
      const amount = isDoc ? d.total : (e.kind === 'pay' ? d.amount + (d.discount || 0) : d.amount);
      const sign = (e.kind === 'buy' || e.kind === 'opening') ? '+' : '−';
      const edited = isDoc && (d.version || 1) > 1;
      tbody.append(h('tr', {},
        h('td', { class: 'td-name' }, d.supplierName || (sup ? sup.name : '—')),
        h('td', {}, h('span', { class: 'badge ' + badgeCls }, label),
          edited ? h('span', { class: 'badge n', title: 'عُدّلت — عدد التعديلات' }, `ع${d.version}`) : null),
        h('td', { class: 'mono' }, fmtDate(d.ts)),
        h('td', { class: 'mono' }, fmtTime(d.ts)),
        h('td', { class: 'td-num', style: { color: e.kind === 'buy' ? 'var(--red)' : 'var(--green)' } }, `${sign} ${fmt(amount)}`),
        h('td', { class: 'td-num', style: { fontWeight: 900, color: e.after > 0 ? 'var(--red)' : 'var(--green)' } }, fmt(e.after)),
                h('td', {}, e.kind === 'opening' ? '' : h('div', { class: 'row-act' },
          isDoc ? h('button', { class: 'icon-btn view', title: 'عرض القائمة', html: icon('eye'), onclick: () => openTab('editpurch', { purchaseId: d.id, readonly: true }) }) : null,
          isDoc
            ? h('button', { class: 'icon-btn edit', title: 'تعديل القائمة', html: icon('edit'), onclick: () => openTab('editpurch', { purchaseId: d.id }) })
            : h('button', { class: 'icon-btn edit', title: 'تعديل المبلغ', html: icon('edit'), onclick: () => editPaymentModal(d) }),
          h('button', { class: 'icon-btn del', title: 'حذف نهائي', html: icon('trash'), onclick: () => isDoc ? deletePurchaseDoc(d) : deletePaymentDoc(d) }))),
      ));
    });
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'اسم المذخر'), h('th', {}, 'نوع العملية'), h('th', {}, 'التاريخ'), h('th', {}, 'وقت الحفظ'),
        h('th', {}, 'المبلغ'), h('th', {}, 'الرصيد المتراكم'), h('th', {}, 'إجراء'))), tbody)));
    if (!evs.length) bodyBox.append(h('div', { class: 'empty-note' }, 'لا عمليات لهذا المذخر في الفترة المحددة'));
    const buys = evs.filter(e => e.kind === 'buy').reduce((s, e) => s + e.doc.total, 0);
    const rets = evs.filter(e => e.kind === 'buyret').reduce((s, e) => s + e.doc.total, 0);
    const pays = evs.filter(e => e.kind === 'pay' || e.kind === 'deposit').reduce((s, e) => s + e.doc.amount + (e.doc.discount || 0), 0);
    footBox.append(
      h('div', { class: 'sum-card b' }, h('label', {}, 'إجمالي المشتريات'), h('b', {}, animSpan(buys))),
      h('div', { class: 'sum-card r' }, h('label', {}, 'إجمالي الاسترجاعات'), h('b', {}, animSpan(rets))),
      h('div', { class: 'sum-card g' }, h('label', {}, 'إجمالي التسديدات والإيداعات'), h('b', {}, animSpan(pays))),
      h('div', { class: 'sum-card big' }, h('label', {}, 'الدين المتراكم الحالي'), h('b', {}, animSpan(sup ? sup.debt || 0 : 0, ' ' + cur()))));
  }
  draw();
  tab.el.append(page);
}

/* عرض/تعديل/حذف عمليات كشف الحساب — الحذف يعكس أثره على المخزون والدين */
function editPaymentModal(pay) {
  const amtInp = h('input', { type: 'number', min: 0, value: pay.amount });
  const discInp = h('input', { type: 'number', min: 0, value: pay.discount || 0 });
  openModal({
    title: `تعديل ${pay.kind === 'deposit' ? 'إيداع' : 'تسديد'} — ${pay.supplierName || ''}`, icon: 'edit',
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field' }, h('label', {}, 'المبلغ'), amtInp),
      h('div', { class: 'f-field' }, h('label', {}, 'الخصم'), discInp)),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'حفظ التعديل', cls: 'g', icon: 'check', big: true, onClick: async c => {
        pay.amount = num(amtInp.value); pay.discount = num(discInp.value);
        await save('payments', pay);
        await recomputeSupplierDebt(pay.supplierId);
        c(); refreshActiveTab(); toast('حُفظ التعديل وأُعيد حساب الدين المتراكم');
      } },
    ],
  });
}
async function deletePurchaseDoc(pu) {
  const yes = await confirmBox(`حذف ${pu.type === 'purchase' ? 'قائمة الشراء' : 'استرجاع الشراء'} رقم ${pu.listNum} نهائياً؟ سيُعكس أثرها على المخزون ويُعاد حساب دين المذخر.`, { danger: true, okLabel: 'حذف نهائي' });
  if (!yes) return;
  for (const it of pu.items || []) {
    const p = findProd(it.productId);
    if (p) { p.stockBase = (p.stockBase || 0) + (pu.type === 'purchase' ? -it.qtyBase : it.qtyBase); await save('products', p); }
  }
  pu.deleted = true; // حذف منطقي — يُزامَن لكل الأجهزة عبر save→push، يُخفى من التقارير، ويبقى قابلاً للتدقيق
  await save('purchases', pu);
  await recomputeSupplierDebt(pu.supplierId);
  refreshActiveTab(); renderSideNav();
  toast('حُذفت القائمة وعُكس أثرها على المخزون والدين', 'b');
}
async function deletePaymentDoc(pay) {
  const yes = await confirmBox('حذف عملية التسديد/الإيداع نهائياً؟ سيُعاد حساب دين المذخر.', { danger: true, okLabel: 'حذف نهائي' });
  if (!yes) return;
  pay.deleted = true;
  await save('payments', pay);
  await recomputeSupplierDebt(pay.supplierId);
  refreshActiveTab();
  toast('حُذفت العملية وأُعيد حساب الدين', 'b');
}

/* ───────────────────────── 25) الإقلاع ───────────────────────── */
async function init() {
  $('#tab-add').innerHTML = icon('plus');
  $('#tab-add').onclick = () => openTab('pos');
  try {
    await DB.open();
    const [accounts, products, sales, purchases, suppliers, payments, customers, settingsArr] = await Promise.all(
      ['accounts','products','sales','purchases','suppliers','payments','customers','settings'].map(s => DB.all(s)));
    state.accounts = accounts; state.products = products; state.sales = sales; state.purchases = purchases;
    state.suppliers = suppliers; state.payments = payments; state.customers = customers;
        /* ★ زبون دائم: دكتورة نادية — يُنشأ مرة واحدة فقط إن لم يكن موجوداً */
    if (!state.customers.some(c => c.id === DR_NADIA_ID)) {
      await save('customers', { id: DR_NADIA_ID, name: 'دكتورة نادية', createdAt: Date.now() });
    }
    state.settings = settingsArr.find(s => s.id === 'app') || { ...DEFAULT_SETTINGS };
    if (!settingsArr.find(s => s.id === 'app')) await DB.put('settings', state.settings);
        /* ترحيل لمرة واحدة: أي كلمة مرور صريحة قديمة → بصمة PBKDF2. لا توجد كلمة مرور افتراضية في الكود إطلاقاً —
       تثبيت جديد بلا حسابات؟ زر «إنشاء حساب» بشاشة الدخول يصنع أول حساب ويمنحه دور المدير تلقائياً */
    for (const a of state.accounts) {
      if (a.password != null) {
        const wasDefault = a.id === 'acc_default_admin' && String(a.password) === '2005';
        await setPassword(a, a.password);
        if (wasDefault) a.mustChangePass = true; // كلمة 2005 المعروفة: إجبار على التغيير عند أول دخول
        await save('accounts', a);
      }
    }
  } catch (e) {
    console.error('init failed:', e);
    const row = $('#accounts-row'); row.innerHTML = '';
    row.append(h('div', { style: { textAlign: 'center', color: 'var(--red)', fontWeight: 800, lineHeight: 2.2 } },
      'تعذّر تحميل قاعدة البيانات المحلية', h('br'), String((e && e.message) || e), h('br'),
      h('button', { class: 'btn g', onclick: () => location.reload() }, 'إعادة المحاولة')));
    return;
  }
     renderLogin(); tickLoginClock();
  Sync.init();
  window.addEventListener('online', () => Sync.init());
}
document.addEventListener('DOMContentLoaded', init);

/* ═══════════════ الحاسبة العلمية العائمة — اضغط + للفتح و Esc للإغلاق ═══════════════ */
const CalcEngine = (() => {
  const S = { deg: true, ans: 0 };
  const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const rad = x => (S.deg ? x * Math.PI / 180 : x);
  const deg = r => (S.deg ? r * 180 / Math.PI : r);
  const FN = {
    sqrt: Math.sqrt, cbrt: Math.cbrt, abs: Math.abs, exp: Math.exp, ln: Math.log, log: Math.log10,
    sin: x => Math.sin(rad(x)), cos: x => Math.cos(rad(x)), tan: x => Math.tan(rad(x)),
    asin: x => deg(Math.asin(x)), acos: x => deg(Math.acos(x)), atan: x => deg(Math.atan(x)),
  };
  const CONST = { pi: Math.PI, e: Math.E };
  const fact = n => {
    if (!Number.isInteger(n) || n < 0 || n > 170) throw new Error('المضروب للأعداد الصحيحة 0–170 فقط');
    let r = 1; for (let i = 2; i <= n; i++) r *= i; return r;
  };
  function tokenize(src) {
    const s = String(src)
      .replace(/[\u0660-\u0669]/g, d => d.charCodeAt(0) - 0x0660)
      .replace(/[\u06F0-\u06F9]/g, d => d.charCodeAt(0) - 0x06F0)
      .replace(/\u066B/g, '.').replace(/[\u066C,]/g, '')
      .replace(/×/g, '*').replace(/÷/g, '/').replace(/[−–]/g, '-')
      .replace(/π/g, 'pi').replace(/√/g, 'sqrt');
    const out = []; let i = 0, m;
    while (i < s.length) {
      const c = s[i], rest = s.slice(i);
      if (/\s/.test(c)) { i++; continue; }
      if ((m = /^(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?/.exec(rest))) { out.push({ t: 'n', v: parseFloat(m[0]) }); i += m[0].length; continue; }
      if ((m = /^[a-zA-Z]+/.exec(rest))) { out.push({ t: 'i', v: m[0].toLowerCase() }); i += m[0].length; continue; }
      if ('+-*/^%!()'.includes(c)) { out.push({ t: 'o', v: c }); i++; continue; }
      throw new Error('رمز غير مفهوم: ' + c);
    }
    return out;
  }
  function parse(tk) {
    let p = 0;
    const peek = () => tk[p], next = () => tk[p++];
    const isOp = v => peek() && peek().t === 'o' && peek().v === v;
    const startsPrimary = () => { const t = peek(); return t && (t.t === 'n' || t.t === 'i' || (t.t === 'o' && t.v === '(')); };
    const close = () => { if (isOp(')')) next(); else if (peek()) throw new Error('قوس ناقص'); };
    function expr() { let v = term(); while (isOp('+') || isOp('-')) { const o = next().v; const r = term(); v = o === '+' ? v + r : v - r; } return v; }
    function term() {
      let v = unary();
      for (;;) {
        if (isOp('*')) { next(); v *= unary(); }
        else if (isOp('/')) { next(); v /= unary(); }
        else if (startsPrimary()) v *= unary();
        else return v;
      }
    }
    function unary() { if (isOp('-')) { next(); return -unary(); } if (isOp('+')) { next(); return unary(); } return power(); }
    function power() { const b = postfix(); if (isOp('^')) { next(); return Math.pow(b, unary()); } return b; }
    function postfix() {
      let v = primary();
      for (;;) {
        if (isOp('!')) { next(); v = fact(v); }
        else if (isOp('%')) { next(); v = v / 100; }
        else return v;
      }
    }
    function primary() {
      const t = next();
      if (!t) throw new Error('العملية ناقصة');
      if (t.t === 'n') return t.v;
      if (t.t === 'o' && t.v === '(') { const v = expr(); close(); return v; }
      if (t.t === 'i') {
        if (t.v === 'ans') return S.ans;
        if (own(CONST, t.v)) return CONST[t.v];
        if (own(FN, t.v)) {
          let a;
          if (isOp('(')) { next(); a = expr(); close(); } else a = postfix();
          return FN[t.v](a);
        }
        throw new Error('دالة غير معروفة: ' + t.v);
      }
      throw new Error('رمز في غير مكانه');
    }
    const v = expr();
    if (p < tk.length) throw new Error('رمز زائد في العملية');
    return v;
  }
  function run(src) {
    try {
      let v = parse(tokenize(src));
      if (typeof v !== 'number' || !isFinite(v)) throw new Error('نتيجة غير معرّفة');
      if (Math.abs(v) < 1e-12) v = 0;
      return { ok: true, value: v };
    } catch (e) { return { ok: false, msg: String((e && e.message) || e) }; }
  }
  const raw = n => String(+n.toPrecision(12));
  const fmtN = n => n.toLocaleString('en-US', { maximumFractionDigits: 10 });
  return { S, run, raw, fmt: fmtN };
})();

let _calcGeo = null, _calcExpr = '';
function closeCalc() {
  const w = document.getElementById('calc-win'); if (!w) return;
  _calcGeo = { x: w._x, y: w._y, w: w.offsetWidth, h: w.offsetHeight };
  _calcExpr = w._inp ? w._inp.value : '';
  w.remove();
}
function openCalc() {
  const g = _calcGeo || { x: 60, y: 90, w: 330, h: 470 };
  const win = h('div', { id: 'calc-win', class: 'calc-win', role: 'dialog', 'aria-label': 'الحاسبة' });
  win.style.width = g.w + 'px'; win.style.height = g.h + 'px';
  let x = g.x, y = g.y, just = false;
  const place = () => {
    x = Math.min(Math.max(0, x), Math.max(0, window.innerWidth - 90));
    y = Math.min(Math.max(0, y), Math.max(0, window.innerHeight - 44));
    win._x = x; win._y = y;
    win.style.transform = `translate(${x}px, ${y}px)`;
  };
  win._place = place;
  const inp = h('input', { class: 'calc-in', type: 'text', dir: 'ltr', spellcheck: 'false', autocomplete: 'off', placeholder: '0' });
  win._inp = inp;
  const res = h('div', { class: 'calc-res' }, '');
  const refresh = () => {
    res.classList.remove('err');
    const src = inp.value.trim();
    if (!src) { res.textContent = ''; return; }
    const r = CalcEngine.run(src);
    res.textContent = r.ok ? '= ' + CalcEngine.fmt(r.value) : '';
  };
  const equals = () => {
    const src = inp.value.trim(); if (!src) return;
    const r = CalcEngine.run(src);
    if (!r.ok) { res.textContent = r.msg; res.classList.add('err'); return; }
    CalcEngine.S.ans = r.value;
    inp.value = CalcEngine.raw(r.value);
    res.textContent = '= ' + CalcEngine.fmt(r.value);
    res.classList.remove('err');
    just = true;
  };
  const ins = t => {
    if (just) { if (!/^[+\-*\/^!%×÷−]/.test(t)) inp.value = ''; just = false; }
    const a = inp.selectionStart == null ? inp.value.length : inp.selectionStart;
    const b = inp.selectionEnd == null ? a : inp.selectionEnd;
    inp.value = inp.value.slice(0, a) + t + inp.value.slice(b);
    const c = a + t.length; inp.setSelectionRange(c, c);
    refresh(); inp.focus();
  };
  const back = () => {
    just = false;
    const a = inp.selectionStart == null ? inp.value.length : inp.selectionStart;
    const b = inp.selectionEnd == null ? a : inp.selectionEnd;
    if (a !== b) { inp.value = inp.value.slice(0, a) + inp.value.slice(b); inp.setSelectionRange(a, a); }
    else if (a > 0) { inp.value = inp.value.slice(0, a - 1) + inp.value.slice(a); inp.setSelectionRange(a - 1, a - 1); }
    refresh(); inp.focus();
  };
  inp.addEventListener('input', () => { just = false; refresh(); });
  inp.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); equals(); return; }
    if (just && e.key.length === 1 && !e.ctrlKey && !e.metaKey && !/[+\-*\/^!%]/.test(e.key)) inp.value = '';
    if (e.key.length === 1 || e.key === 'Backspace' || e.key === 'Delete') just = false;
  });

  const D = d => [d, d, 'n'];
  const KEYS = [
    ['DEG', 'deg', 'fn'], ['(', '(', 'fn'], [')', ')', 'fn'], ['⌫', 'bs', 'op'], ['C', 'clr', 'clr'],
    ['sin', 'sin(', 'fn'], ['cos', 'cos(', 'fn'], ['tan', 'tan(', 'fn'], ['π', 'π', 'fn'], ['e', 'e', 'fn'],
    ['√', '√(', 'fn'], ['x²', '^2', 'fn'], ['xʸ', '^', 'fn'], ['ln', 'ln(', 'fn'], ['log', 'log(', 'fn'],
    D('7'), D('8'), D('9'), ['÷', '÷', 'op'], ['n!', '!', 'fn'],
    D('4'), D('5'), D('6'), ['×', '×', 'op'], ['%', '%', 'fn'],
    D('1'), D('2'), D('3'), ['−', '−', 'op'], ['Ans', 'Ans', 'fn'],
    D('0'), ['.', '.', 'n'], ['00', '00', 'n'], ['+', '+', 'op'], ['=', '=', 'eq'],
  ];
  const keys = h('div', { class: 'calc-keys' });
  KEYS.forEach(([label, act, cls]) => {
    const b = h('button', { type: 'button', tabindex: '-1', class: 'calc-k ' + cls }, label);
    if (act === 'deg') b.textContent = CalcEngine.S.deg ? 'DEG' : 'RAD';
    b.addEventListener('click', () => {
      if (act === 'bs') back();
      else if (act === 'clr') { inp.value = ''; just = false; refresh(); inp.focus(); }
      else if (act === '=') { equals(); inp.focus(); }
      else if (act === 'deg') { CalcEngine.S.deg = !CalcEngine.S.deg; b.textContent = CalcEngine.S.deg ? 'DEG' : 'RAD'; refresh(); inp.focus(); }
      else ins(act);
    });
    keys.append(b);
  });

  const head = h('div', { class: 'calc-head' },
    h('span', { class: 'calc-title' }, 'الحاسبة'),
    h('small', {}, '+ للفتح • Esc للإغلاق'),
    h('button', { type: 'button', tabindex: '-1', class: 'calc-x', title: 'إغلاق', html: icon('close'), onclick: closeCalc }));
  head.addEventListener('pointerdown', e => {
    if (e.target.closest('.calc-x')) return;
    e.preventDefault();
    head.setPointerCapture(e.pointerId);
    const sx = e.clientX - x, sy = e.clientY - y;
    const mv = ev => { x = ev.clientX - sx; y = ev.clientY - sy; place(); };
    const up = () => {
      head.removeEventListener('pointermove', mv);
      head.removeEventListener('pointerup', up);
      head.removeEventListener('pointercancel', up);
      inp.focus();
    };
    head.addEventListener('pointermove', mv);
    head.addEventListener('pointerup', up);
    head.addEventListener('pointercancel', up);
  });
  win.addEventListener('keydown', e => {
    if (e.key === '+') return;            /* يمر للمستمع العام — ويُحجب هناك داخل الحقول فيُكتب عادياً */
    e.stopPropagation();                   /* لا يتسرّب أي ضغط إلى نقطة البيع */
    if (e.key === 'Escape') { e.preventDefault(); closeCalc(); }
  });
  win.addEventListener('mousedown', e => { if (e.target.closest('.calc-k')) e.preventDefault(); });
  win.addEventListener('mouseup', () => { if (document.activeElement !== inp) inp.focus(); });

  win.append(head, h('div', { class: 'calc-disp' }, inp, res), keys);
  document.body.append(win);
  place();
  inp.value = _calcExpr || '';
  refresh();
  setTimeout(() => inp.focus(), 0);
}
function toggleCalc() { if (document.getElementById('calc-win')) closeCalc(); else openCalc(); }
document.addEventListener('keydown', e => {
  if (e.key !== '+' || e.ctrlKey || e.altKey || e.metaKey) return;
  const ae2 = e.target;
  if (ae2 && (/^(INPUT|TEXTAREA|SELECT)$/.test(ae2.tagName) || ae2.isContentEditable)) return;   /* داخل حقل إدخال = يُكتب + عادياً */
  e.preventDefault();
  if (!state.session && !document.getElementById('calc-win')) return;   /* لا تفتح قبل تسجيل الدخول */
  toggleCalc();
});
window.addEventListener('resize', () => { const w = document.getElementById('calc-win'); if (w && w._place) w._place(); });
/* ═══ الوضع النهاري / الليلي — مفتاح شمس (يمين) وقمر (يسار) مجاور لأزرار النافذة، يُحفظ محلياً ═══ */
const THEME_SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.4M12 19.1v2.4M2.5 12h2.4M19.1 12h2.4M4.9 4.9l1.7 1.7M17.4 17.4l1.7 1.7M19.1 4.9l-1.7 1.7M6.6 17.4l-1.7 1.7"/></svg>';
const THEME_MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11z"/></svg>';
function themeToggle() {
  const isDark = () => document.documentElement.getAttribute('data-theme') === 'dark';
  const btn = h('button', { class: 'theme-sw' + (isDark() ? ' on' : ''), title: 'التبديل بين الوضع النهاري والليلي' });
  btn.append(h('span', { class: 'th-sun', html: THEME_SUN }), h('span', { class: 'th-moon', html: THEME_MOON }));
  btn.addEventListener('click', () => {
    const dark = !isDark();
    if (dark) document.documentElement.setAttribute('data-theme', 'dark');
    else document.documentElement.removeAttribute('data-theme');
    try { localStorage.setItem('ds_theme', dark ? 'dark' : 'light'); } catch (e) {}
    btn.classList.toggle('on', dark);
  });
  return btn;
}

/* ═══ أزرار النافذة (تصغير / إغلاق) ═══ */
const WIN_MIN_IC = '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M5 18h14"/></svg>';
function winControls() {
  if (!window.desktop) return null;   // خارج Electron لا تظهر
  return h('div', { class: 'win-ctl' },
    h('button', { class: 'tb-win tb-min', title: 'تصغير إلى سطح المكتب', html: WIN_MIN_IC, onclick: () => window.desktop.minimize() }),
    h('button', { class: 'tb-win tb-quit', title: 'إغلاق البرنامج', html: icon('close'), onclick: async () => {
      if (await confirmBox('إغلاق البرنامج؟', { danger: true, okLabel: 'إغلاق' })) window.desktop.close();
    } }));
}
(function mountLoginWinControls() {
  const ls = $('#login-screen'), wc = winControls();
  if (ls && wc && !ls.querySelector('.win-ctl')) { wc.classList.add('floating'); ls.append(wc); }
})();

/* ═══ التحديث التلقائي — الواجهة ═══ */
(function initUpdater() {
  const U = window.desktop && window.desktop.update; if (!U) return;
  let box = null;
  const closeBox = () => { if (box) { box.remove(); box = null; } };
  function show(info) {
    closeBox();
    const fill = h('i'), bar = h('div', { class: 'upd-bar hidden' }, fill);
    const msg = h('p', {}, 'يتوفر تحديث جديد لنظام المبيعات. يُنصح بالتحديث للحصول على آخر التحسينات.');
    const bUpd = h('button', { class: 'btn g big' }, 'تحديث');
    const bIgn = h('button', { class: 'btn n' }, 'تجاهل');
    bIgn.onclick = () => { U.ignore(); closeBox(); toast('سيظهر التحديث مجدداً بعد 15 دقيقة', 'b'); };
    bUpd.onclick = async () => {
      const busy = tabs.some(t => t.type === 'pos' && t.state.cart && t.state.cart.length);
      if (busy && !(await confirmBox('توجد قوائم بيع غير منتهية ستُفقد عند إعادة التشغيل. المتابعة؟', { danger: true, okLabel: 'متابعة' }))) return;
      bUpd.disabled = bIgn.disabled = true; bar.classList.remove('hidden');
      msg.textContent = 'جارٍ تنزيل التحديث… لا تُغلق البرنامج.';
      U.download();
    };
    box = h('div', { id: 'upd-overlay' }, h('div', { class: 'upd-card', role: 'dialog' },
      h('h3', {}, `تحديث جديد — الإصدار ${info.version}`), msg,
      info.notes ? h('pre', { class: 'upd-notes' }, info.notes) : null, bar,
      h('div', { class: 'upd-act' }, bIgn, bUpd)));
    box._fill = fill; box._msg = msg; box._btns = [bUpd, bIgn];
    document.body.append(box);
  }
  U.onAvailable(show);
  U.onProgress(p => { if (box) box._fill.style.width = p.percent + '%'; });
  U.onReady(() => { if (box) box._msg.textContent = 'اكتمل التنزيل — سيُعاد تشغيل البرنامج الآن…'; });
  U.onError(m => { if (box) { box._msg.textContent = 'تعذّر التحديث: ' + m; box._btns.forEach(b => b.disabled = false); } });
  U.getPending().then(i => { if (i) show(i); }).catch(() => {});
})();

