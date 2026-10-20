/* ═══════════════════════════════════════════════════════════════
   الماسح الذكي — قراءة الفواتير الورقية بالصور (Gemini API)
   • يرفع الصورة → يستخرج (الاسم، الشركة، الكمية، السعر) بصيغة JSON
   • يبحث في مخزن الصيدلية أولاً ويمنع إنشاء أي صنف مكرر
   • الأصناف غير الموجودة تُنشأ بنفس أسلوب أصنافك (براند/شركة/شكل/وحدة/سعر + باركود مولّد)
   • جدول مراجعة قابل للتعديل → استيراد مباشر إلى قائمة الشراء
   ═══════════════════════════════════════════════════════════════ */
window.InvoiceScanner = (() => {

  
  const PROMPT = `You are an expert pharmaceutical invoice OCR system for an Iraqi pharmacy.
Analyze this invoice image and extract EVERY product line item.
Return ONLY a JSON object (no markdown, no explanation) in this exact shape:
{"supplier":"","list_no":"","items":[{"name":"","sci":"","dose_value":"","dose_unit":"","form":"","expiry":"","company":"","quantity":0,"bonus_qty":0,"bonus_on":"","unit_price":0,"total":0}]}
Header rules — both are printed at the TOP of the sheet, outside the item table, and are the most valuable data on the page:
- supplier: the wholesaler name exactly as printed. Keep its own script (Arabic stays Arabic, English stays English). Copy ONLY the name — no address, phone, date, slogan or logo text. Use "" when absent.
- list_no: the list / bill number printed at the top after words like رقم القائمة، قائمة رقم، سند رقم، رقم الفاتورة، INV NO، BILL NO، INVOICE NO، NO:. Output digits only exactly as printed (Arabic-Indic ١٢٣ is fine), e.g. "154". Never use a date, a phone number or a money total as list_no. Use "" when absent.
Splitting rules — these are the most important rules:
- Every printed strength and dosage form belongs to its OWN field, NEVER inside "name".
  "GLUCOPHAGE 850 MG TAB" -> name:"Glucophage", dose_value:"850", dose_unit:"mg", form:"Tab".
  "AMOXICILLIN 500MG CAPS" -> name:"Amoxicillin", dose_value:"500", dose_unit:"mg", form:"Cap".
  "CTILAXIN 1GR INJ"       -> name:"Ctilaxin", dose_value:"1", dose_unit:"g", form:"Amp".
  "DERMOBELNE CREAM 15G"   -> name:"Dermobelne", dose_value:"", dose_unit:"", form:"Cream" (15G is pack size, not strength).
- name: trade/brand name ONLY, in English (Latin) letters exactly as printed, Left-to-Right. No Arabic, no company, no strength, no form, no pack size.
- If the manufacturer looks glued to the front or back of the brand string, put ONLY the brand in name and the manufacturer in company.
- If one brand appears several times with different strengths, keep each as its own line and fill dose_value + dose_unit for each.
Field rules:
- dose_value: digits only as a string (e.g. "850", "0.25", "10"). Use "" when no strength is printed.
- dose_unit: exactly one of mg, mcg, g, ml, %, IU (lowercase except IU). For "250mg/5ml" use dose_value "250" + dose_unit "mg". Use "" when unknown.
- form: one of Tab, Cap, Amp, Vial, Gum, Syrup, Susp, Supp, Drops, Cream, Oint, Gel, Sachet, Spray, Inhaler, Patch, Infusion. Otherwise "".
- sci: scientific (generic) name if printed, else "".
- expiry: printed expiry for this line normalized to "YYYY-MM", else "".
- company: manufacturer/brand owner as printed, else "".
- quantity: PAID pieces only (the bonus pieces must NOT be inside it). unit_price: price per paid piece. total: line total. Plain numbers, 0 when unreadable.
Bonus rules:
- Written inline like "10+1", "12(1)", "24+2 free": quantity = the paid number, bonus_qty = the free number.
- Printed on its own line (under words like BONUS, FREE, GIFT, OFFER, هدية, مجاني, بونص) or a line that has quantity but NO unit_price and NO total: keep it as a line with unit_price 0, total 0, bonus_qty = its free pieces, bonus_on = the brand name of the paid line it belongs to (same brand, usually the line above).
- Never count bonus pieces as purchased quantity and never invent a price for a bonus line.
Ignore footers, item-table numbers, taxes, shipping and any non-product line. Never invent a product that is not printed.
Output must start with { and end with } and nothing else.`;

  /* تطبيع النص: توحيد الهمزات والتاء والياء + إزالة التشكيل والرموز — لمطابقة دقيقة */
  const norm = s => String(s == null ? '' : s)
    .toLowerCase()
    .replace(/[\u064B-\u0652\u0640\u0670]/g, '')
    .replace(/[إأآٱا]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/ؤ/g, 'و').replace(/ئ/g, 'ي')
    .replace(/[^a-z0-9\u0600-\u06FF]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  /* تشابه توكني (Dice) — للتغلب على اختلاف ترتيب الكلمات والحروف الزائدة */
  function sim(a, b) {
    const A = new Set(String(a).split(' ').filter(Boolean));
    const B = new Set(String(b).split(' ').filter(Boolean));
    if (!A.size || !B.size) return 0;
    let inter = 0; A.forEach(t => { if (B.has(t)) inter++; });
    return (2 * inter) / (A.size + B.size);
  }

    /* ★ استخراج النص اللاتيني داخل الأقواس: «بايونير (Pioneer)» ← pioneer */
  const latinOf = s => { const m = String(s || '').match(/[(\[]([A-Za-z][A-Za-z0-9&.\- ]{1,40})[)\]]/); return m ? norm(m[1]) : ''; };

  /* ★ حل مشكلة الشركات: المقروء إنكليزي والمسجّل «عربي (إنكليزي)» —
     المطابقة على النص الكامل + على اللاتيني داخل الأقواس معاً */
  function resolveCompany(scanned) {
    const raw = String(scanned || '').trim();
    if (!raw) return '';
    const cn = norm(raw);
    const cs = state.settings.companies || [];
    let hit = cs.find(c => norm(c.name) === cn);
    if (!hit) hit = cs.find(c => { const l = latinOf(c.name); return l && (l === cn || l.includes(cn) || cn.includes(l)); });
    if (!hit) hit = cs.find(c => { const n2 = norm(c.name); return n2 && (n2.includes(cn) || cn.includes(n2)); });
    return hit ? hit.name : raw;
  }

  /* نقاط إضافية عند تطابق الشركة (تكسر التعادل بين أسماء متشابهة) */
  function companyBonus(p, company) {
    const cn = norm(company); if (!cn) return 0;
    const full = norm(p.company), lat = latinOf(p.company);
    if (full && full === cn) return 20;
    if (lat && (lat === cn || lat.includes(cn) || cn.includes(lat))) return 20;
    if (full && (full.includes(cn) || cn.includes(full))) return 10;
    return 0;
  }

  /* ★ توحيد الإكسباير إلى YYYY-MM من أي صيغة مكتوبة في ورقة المذخر (05/2027، 2027-05، 05-27…) */
  function normExpiry(v) {
    const s = String(v || '').trim();
    if (!s) return '';
    let y, mo;
    const m = s.match(/(\d{4})[\s\/\-.](\d{1,2})/) || s.match(/(\d{1,2})[\s\/\-.](\d{2,4})/);
    if (m) {
      if (m[1].length === 4) { y = +m[1]; mo = +m[2]; }
      else { mo = +m[1]; y = +m[2]; if (y < 100) y += 2000; }
    } else {
      const y4 = s.match(/(20\d{2})/);
      if (y4) { y = +y4[1]; mo = 12; } else return '';
    }
    if (!(y >= 2020 && y <= 2060) || !(mo >= 1 && mo <= 12)) return '';
    return `${y}-${String(mo).padStart(2, '0')}`;
  }

  /* ★ الاسم التجاري المجرَّد: تُحذف الجرعة والشكل الصيدلاني وكل نص بين قوسين —
     فيُطابَق «Glucophage 850 mg Tab» (المكتوب في خانة الاسم) على «Glucophage 850mg Tab» المسجَّل بالمخزن،
     ولا تُحاسب الشركة لو كُتبت خطأً داخل حقل الاسم */
  const BRACKET_RE = /\([^)]*\)|\[[^\]]*\]/g;
  const STRENGTH_RE = /\d+(?:[.,]\d+)?\s*(?:mg|mcg|ug|gram|grams|g|ml|iu|ui|units?|kiu|%)+(?:\s*\/\s*\d+\s*(?:ml|dose|doses|tab|s)?)?%?/gi;
  const FORMTXT_RE = /\b(?:tablets?|tabs?|capsules?|caps?|ampoules?|ampuls?|amps?|vials?|syrups?|suspensions?|susp|drops?|cream|ointment|oint|gel|suppositories?|supp|sachets?|sprays?|inhalers?|patches?|infusions?|solution|sln|inj)\b/gi;
  const FORM_SYNS = { tab: 'tab', tabs: 'tab', tablet: 'tab', cap: 'cap', caps: 'cap', capsule: 'cap', gum: 'gum',
    amp: 'amp', ampul: 'amp', ampoule: 'amp', vial: 'vial', syrup: 'syrup', sirup: 'syrup', syp: 'syrup',
    susp: 'susp', suspension: 'susp', drops: 'drops', drop: 'drops', cream: 'cream', oint: 'oint', ointment: 'oint',
    gel: 'gel', supp: 'supp', suppository: 'supp', sachet: 'sachet', spray: 'spray', inhaler: 'inhaler',
    patch: 'patch', infusion: 'infusion', solution: 'solution', sln: 'solution', inj: 'solution' };
  /* ★ شركة كُتبت داخل حقل الاسم: تُنقل إلى حقل الشركة فلا تُفقد المطابقة (ولا تُمسح من الاسم المعروض) */
  function liftCompanyFromName(brand, company) {
    const cs = new Set(norm(company).split(' ').filter(w => w.length >= 4));
    if (!cs.size) return String(brand || '');
    const keep = String(brand || '').split(/\s+/).filter(w => w && !cs.has(norm(w)));
    return keep.length ? keep.join(' ') : String(brand || '');
  }
  const formKey = s => { const k = norm(s).split(' ')[0] || ''; return FORM_SYNS[k] || k; };
  function brandCore(s) {
    return norm(String(s || '').replace(BRACKET_RE, ' ').replace(STRENGTH_RE, ' ').replace(FORMTXT_RE, ' '))
      .replace(/\s+/g, ' ').trim();
  }
  /* رقم الجرعة ووحدها من أي نص: «850mg»، «250mg/5ml»، «10 %» (بلا norm — لأن norm يمسح علامة %) */
  function doseParts(s) {
    const m = String(s || '').toLowerCase().match(/(\d+(?:[.,]\d+)?)\s*(mg|mcg|ug|iu|ui|ml|g|%)/);
    if (!m) return { v: 0, u: '' };
    return { v: parseFloat(m[1].replace(',', '.')), u: (m[2] === 'ui' ? 'iu' : m[2] === 'ug' ? 'mcg' : m[2]) };
  }

  /* ★ المطابقة على مرحلتين كما طلبت: (١) الاسم التجاري وحده يجلب كل المرشحين — كل جرعات الغلوكوفاج تدخل معاً،
     (٢) الشركة/الجرعة/الشكل تحسم أيها المقصود. الجرعة المختلفة ترفض، وغيابها من الطرفين لا يرفض */
  function matchList(name, company, dose, form) {
    const core = brandCore(name);
    if (!core) return [];
    const bare = brandCore(liftCompanyFromName(name, company)) || core;   /* الاسم بعد تنحية الشركة */
    const dp = doseParts([dose, name].join(' '));
    const ck = formKey(form);
    const rows = [];
    state.products.filter(p => !p.deleted).forEach(p => {
      const c = brandCore(p.brandName);
      if (!c) return;
      let ns = (c === core || c === bare) ? 60 : 0;
      if (!ns) {
        const a = c.split(' ')[0], b = core.split(' ')[0];
        if (a.length >= 3 && b.length >= 3) {
          if (a === b || c.startsWith(core) || core.startsWith(c)) ns = 45;
          else if (c.includes(core) || core.includes(c)) ns = 34;
          else { const t = _tokScore(b, a, true); if (t >= 30) ns = 26; }
        }
      }
      if (!ns) return;
      const pd = doseParts(p.dose || ''), pk = formKey(p.form);
      const cb = companyBonus(p, company);
      const marks = { name: ns, company: cb >= 10, dose: (!dp.v || !pd.v) ? null : dp.v === pd.v,
        form: (!ck || !pk) ? null : ck === pk };
      rows.push({ p, marks, score: ns + cb
        + (marks.dose === true ? 34 : marks.dose === false ? -60 : 0)
        + (marks.form === true ? 14 : marks.form === false ? -25 : 0) });
    });
    rows.sort((a, b) => b.score - a.score || a.p.brandName.length - b.p.brandName.length);
    return rows.slice(0, 8);
  }
  /* القرار: لا اختيار إلا بحجّة — تعادل بين جرعتين يعني «سؤالك»، لا تخمين */
  function bestMatch(name, company, dose, form) {
    const ls = matchList(name, company, dose, form);
    if (!ls.length) return null;
    if (ls.length === 1) return ls[0].score >= 26 ? ls[0].p : null;
    const t = ls[0], n = ls[1];
    if (t.marks.dose === true && (t.marks.company || t.marks.form === true)) return t.p;
    if (t.marks.name >= 60 && t.score - n.score >= 25) return t.p;
    if (t.score - n.score >= 40) return t.p;
    return null;
  }
  /* ★ ربط حيّ لكل سطر: يحفظ المرشحين والعلامات (✓شركة ✓جرعة ✓شكل) ليراها المستخدم قبل الاستيراد */
  function autoLink(it) {
    const ls = matchList(it.name, it.company, it.dose, it.form);
    it.marks = ls.length ? ls[0].marks : null;
    it.alts = ls.slice(0, 8).map(o => o.p.id);
    const m = bestMatch(it.name, it.company, it.dose, it.form);
    it.ambiguous = !m && ls.length > 1;
    if (!it.forceNew) it.productId = m ? m.id : null;
    return it.productId ? findProd(it.productId) : null;
  }

  /* ★ بونص الورقة («10+1» أو صف مجاني بلا سعر): يبقى سطر شراء واحداً ونسأل مرة واحدة —
     «نعم» تبني دفتر البونص تلقائياً بعد حفظ القائمة، و«لا» يتركها شراءً عادياً */
  function askBonus(lots) {
    return new Promise(res => {
      if (!lots || !lots.length) return res([]);
      const body = h('div', { class: 'pm-bonus' },
        h('div', { class: 'bn-tip' }, 'عدد البونص لا يُضاف إلى عدد الشراء في القائمة — يُسجَّل في دفتر البونص، يُزاد في المخزون، ويظهر في تقارير البونص وربيحه.'),
        ...lots.map(L => h('div', { class: 'pm-brow' },
          h('b', {}, L.productName),
          h('span', { dir: 'ltr' }, `${fmt(L.buyQty)} ${L.unitName || ''} → ${fmt(L.bonusQty)} مجاناً`),
          h('span', {}, `${Math.round(L.bonusQty / Math.max(1e-6, L.buyQty) * 10000) / 100}% مجاناً`))));
      openModal({ title: 'رُصد بونص في القائمة الورقية', icon: 'gift', wide: true, body,
        actions: [
          { label: 'لا، شراء عادي', cls: 'n', onClick: c => { c(); res([]); } },
          { label: 'نعم، أضف البونص', cls: 'g', icon: 'gift', big: true, onClick: c => { c(); res(lots); } },
        ],
        onClose: () => res([]) });
    });
  }

  /* شركة جديدة تُسجَّل في قائمة الشركات (نفس مصدر صفحة الصنف) */
  async function rememberCompany(name) {
    const nm = String(name || '').trim();
    if (!nm) return;
    const cs = state.settings.companies = state.settings.companies || [];
    if (cs.some(c => c.name.trim().toLowerCase() === nm.toLowerCase())) return;
    cs.push({ name: nm, country: '' });
    await save('settings', state.settings);
  }

  /* ★ صنف جديد من الماسح — الاسم: التجاري + الجرعة + الشكل (إنكليزي LTR)، والجرعة رقم + وحدة كما في صفحة الصنف،
     والشركة لا تدخل حقل الاسم أبداً. الصنف الموجود لا يُلمَس هنا: زيادته ومتوسط تكلفتهما تحدث في «حفظ قائمة الشراء» */
  async function createProduct(it) {
    const price = +it.price || 0;
    const profit = +(state.settings.profitPct ?? 30);
    const company = resolveCompany(it.company);
    const brand = liftCompanyFromName(String(it.name || '').trim(), company);
    const doseV = String(it.doseV || '').replace(/[^\d.]/g, '');
    const doseU = String(it.doseU || '').replace(/[^\w%/.+-]/g, '');
    const dose = doseV ? doseV + doseU : String(it.dose || '').trim();
    let form = String(it.form || '').trim();
    if (form && !FORMS.includes(form)) FORMS.push(form); // شكل جديد يُضاف لقائمة الأشكال تلقائياً
    const p = {
      id: uid(),
      brandName: [brand, dose, form].filter(Boolean).join(' '),
      scientificName: String(it.sci || '').trim(),
      barcodes: [genBarcode()],
      form: form || 'Tab', dose, expiry: normExpiry(it.expiry), featured: false,
      company, country: '',
      units: [{ name: 'قطعة', perNext: 1 }],
      purchasePriceTop: price,
      salePriceBase: price ? Math.round(price * (1 + profit / 100)) : 0,
      stockBase: 0, createdAt: Date.now(), fromScanner: true,
      stockLog: [],
    };
    await rememberCompany(p.company);
    await save('products', p);
    it.productId = p.id;
    return p;
  }

  /* ★ لا موديلات ثابتة: تُقرأ قائمة الموديلات المتاحة فعلاً لمفتاحك ثم تُرتَّب بالأفضلية */
  const PREFERRED = ['gemini-flash-latest', 'gemini-2.5-flash', 'gemini-flash-lite-latest', 'gemini-2.5-flash-lite', 'gemini-2.0-flash', 'gemini-2.0-flash-lite'];
  const FALLBACK  = ['gemini-flash-latest', 'gemini-2.5-flash', 'gemini-2.5-flash-lite'];
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  let modelCache = { key: '', list: null, ts: 0 };

  async function listModels(apiKey) {
    if (modelCache.list && modelCache.key === apiKey && Date.now() - modelCache.ts < 600000) return modelCache.list;
    try {
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000&key=${encodeURIComponent(apiKey)}`);
      if (!r.ok) return null;
      const d = await r.json();
      const names = (d.models || [])
        .filter(m => (m.supportedGenerationMethods || []).includes('generateContent'))
        .map(m => String(m.name || '').replace(/^models\//, ''));
      modelCache = { key: apiKey, list: names, ts: Date.now() };
      return names;
    } catch (_) { return null; }
  }
  function orderModels(avail) {
    if (!avail || !avail.length) return FALLBACK;
    const pref = PREFERRED.filter(n => avail.includes(n));
    const rest = avail.filter(n => /flash/.test(n) && !/(preview|exp|tts|image|live|audio|thinking|robotics|computer|embedding|learnlm)/.test(n) && !pref.includes(n)).sort().reverse();
    const out = [...pref, ...rest].slice(0, 6);
    return out.length ? out : FALLBACK;
  }
  const textOf = d => {
    const c0 = d && d.candidates && d.candidates[0];
    return ((c0 && c0.content && c0.content.parts) || []).map(p => p.text || '').join('');
  };

  /* نداء Gemini: تبديل ذكي + إعادة محاولة عند الازدحام/الحصة + إظهار السبب الحقيقي لكل موديل */
  async function callGemini(base64, mime, apiKey) {
    const models = orderModels(await listModels(apiKey));
    const errors = [];
    for (const model of models) {
      for (let attempt = 0; attempt < 2; attempt++) {
        const gen = { temperature: 0, maxOutputTokens: 16384, responseMimeType: 'application/json' };
        if (model === 'gemini-2.5-flash') gen.thinkingConfig = { thinkingBudget: 0 }; // يمنع استهلاك التوكنز في «التفكير»
        let res;
        try {
          res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ role: 'user', parts: [{ text: PROMPT }, { inlineData: { mimeType: mime, data: base64 } }] }],
              generationConfig: gen,
            }),
          });
        } catch (e) { errors.push(`${model}: تعذّر الاتصال بالإنترنت`); break; }
        if (res.ok) {
          const data = await res.json();
          if (textOf(data).trim()) return data;
          const why = (data.promptFeedback && data.promptFeedback.blockReason) || (data.candidates && data.candidates[0] && data.candidates[0].finishReason) || 'ردّ فارغ';
          errors.push(`${model}: ${why}`); break;
        }
        const err = await res.json().catch(() => ({}));
        const msg = String((err && err.error && err.error.message) || '').slice(0, 140);
        if (res.status === 401 || res.status === 403 || (res.status === 400 && /api key/i.test(msg)))
          throw new Error(`المفتاح مرفوض (${res.status}): ${msg}`);
        errors.push(`${model} (${res.status}): ${msg || 'خطأ'}`);
        if ([429, 500, 503].includes(res.status) && attempt === 0) { await sleep(2500); continue; }
        break;
      }
    }
    throw new Error(errors.length ? errors.join(' ║ ') : 'تعذّر الاتصال بخدمة القراءة');
  }

  /* ★ صورة واحدة تكفي للغرضين: تقرأها Gemini وتُحفظ «نسخة ورقية» للقائمة —
     تُضغط تلقائياً حتى تنزل تحت سقف خفيف (≈1.8MB) فيبقى رفعها وسحبها من السحابة سريعاً */
  function prepImage(file) {
    return new Promise(resolve => {
      const raw = () => {
        const r = new FileReader();
        r.onload = () => resolve({ dataUrl: r.result, base64: String(r.result).split(',')[1], mime: file.type || 'image/jpeg' });
        r.onerror = () => resolve(null);
        r.readAsDataURL(file);
      };
      const url = URL.createObjectURL(file);
      const img = new Image();
      const shot = (side, q) => {
        try {
          const k = Math.min(1, side / Math.max(img.naturalWidth || side, img.naturalHeight || side));
          const c = document.createElement('canvas');
          c.width = Math.round((img.naturalWidth || side) * k); c.height = Math.round((img.naturalHeight || side) * k);
          const ctx = c.getContext('2d'); ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, c.width, c.height);
          ctx.drawImage(img, 0, 0, c.width, c.height);
          return c.toDataURL('image/jpeg', q);
        } catch (_) { return null; }
      };
      img.onload = () => {
        let out = null;
        for (const [side, q] of [[1700, .82], [1400, .74], [1100, .66]]) {
          out = shot(side, q);
          if (!out) break;
          if (out.length <= 2400000) break;   /* صورة أقصر ضلعاً = نص أصعب: نبدأ بالأكبر وننزل فقط عند الحاجة */
        }
        URL.revokeObjectURL(url);
        if (!out) return raw();
        resolve({ dataUrl: out, base64: String(out).split(',')[1], mime: 'image/jpeg' });
      };
      img.onerror = () => { URL.revokeObjectURL(url); raw(); };
      img.src = url;
    });
  }
  function parseItems(data) {
    const c0 = data && data.candidates && data.candidates[0];
    let text = (c0 && c0.content && c0.content.parts && c0.content.parts[0] && c0.content.parts[0].text) || '';
    text = text.replace(/```json|```/g, '').trim();
    const s = text.indexOf('{'), e = text.lastIndexOf('}');
    let obj = null;
    if (s >= 0 && e >= 0) { try { obj = JSON.parse(text.slice(s, e + 1)); } catch (_) {} }
    if (!obj) { /* احتياط: بعض الردود مصفوفة مجرّدة */
      const as = text.indexOf('['), ae = text.lastIndexOf(']');
      if (as >= 0 && ae >= 0) obj = { supplier: '', items: JSON.parse(text.slice(as, ae + 1)) };
      else throw new Error('تعذّر استخراج بيانات من الصورة');
    }
    /* ★ الجرعة تُخزَّن رقماً + وحدة (نفس خانة «الجرعة» في صفحة الصنف): «850» + «mg» */
    const items = (obj.items || []).map(x => {
      let dv = String(x.dose_value != null ? x.dose_value : (x.doseValue != null ? x.doseValue : '')).trim();
      let du = String(x.dose_unit != null ? x.dose_unit : (x.doseUnit != null ? x.doseUnit : '')).trim();
      if (!dv && !du) {
        const t = String(x.dose || '').trim(); const p = doseParts(t);
        if (p.v) { dv = String(p.v); du = p.u; }
        else if (/^\d+(?:[.,]\d+)?$/.test(t)) dv = t.replace(',', '.');
      }
      dv = dv.replace(/[^\d.]/g, '');
      du = du.replace(/[^\w/%+-]/g, '');
      return {
        name: String(x.name || '').trim(),
        sci: String(x.sci || x.scientific || '').trim(),
        doseV: dv, doseU: du, dose: dv + du,
        form: String(x.form || '').trim(),
        expiry: String(x.expiry || '').trim(),
        company: String(x.company || '').trim(),
        qty: +x.quantity || +x.qty || 0,
        bonusQty: Math.max(0, +x.bonus_qty || +x.bonusQty || 0),
        bonusOn: String(x.bonus_on || x.bonusOn || '').trim(),
        price: +x.unit_price || +x.price || 0,
        total: +x.total || 0,
      };
    }).filter(x => x.name);
    return { supplier: String(obj.supplier || '').trim(), listNum: String(obj.list_no || obj.listNo || obj.list_num || '').trim(), items };
  }

  /* ★ البونص يرجع إلى سطر الشراء: صف مجاني بلا سعر أو «10+1» → سطر واحد في القائمة فقط */
  function mergeBonus(list) {
    const out = [];
    const paid = list.filter(it => (+it.price || 0) > 0 || (+it.total || 0) > 0);
    list.forEach(it => {
      if (it.folded) return;                                       /* السطر المدموج سابقاً لا يُدمج مرتين */
      const free = Math.max(0, +it.bonusQty || 0);
      const noCost = !(+it.price > 0) && !(+it.total > 0);
      const worded = /(?:\b(?:bonus|free|gift|offer)\b|هدية|مجاني|مجانا|بونص)/i.test(`${it.name} ${it.bonusOn}`);
      if (!free && !noCost) { out.push(it); return; }
      const key = brandCore(it.bonusOn || it.name);
      const parent = paid.find(p => {
        if (p === it || p.folded) return false;
        const c = brandCore(p.name);
        return !!c && !!key && (c === key || c.includes(key) || key.includes(c));
      });
      if (parent && (free > 0 || worded || it.bonusOn)) {
        parent.bonusQty = free + Math.max(0, +it.qty || 0) + Math.max(0, +parent.bonusQty || 0);
        if (!parent.expiry && it.expiry) parent.expiry = it.expiry;
        if (!parent.company && it.company) parent.company = it.company;
        it.folded = true;
        return;
      }
      out.push(it);
    });
    return out;
  }
  /* دفتر البونص الجاهز للحفظ: بعد أن تُحدَّد المواد (موجودة أو جديدة) */
  function lotsOf(list) {
    return list.reduce((a, it) => {
      const bq = Math.max(0, +it.bonusQty || 0);
      if (!(bq > 0) || !it.productId) return a;
      const p = findProd(it.productId);
      if (!(+it.qty > 0)) { toast(`سطر «${it.name}» فيه بونص بلا عدد شراء — أكمل الكمية ليُسجَّل البونص`, 'r'); return a; }
      a.push({ productId: it.productId, productName: (p && p.brandName) || it.name,
        unitIdx: 0, unitName: p ? p.units[0].name : 'قطعة', buyQty: +it.qty, bonusQty: bq,
        buyPrice: Math.max(0, +it.price || 0), note: 'بونص مقروء من قائمة ورقية' });
      return a;
    }, []);
  }

  function mount(rootEl, { getKey, onImport }) {
    let items = [], supplier = '', listNum = '', lastImage = '';   // supplier + listNum من رأس الورقة — يملآن قائمة الشراء تلقائياً
    rootEl.innerHTML = '';

    const fileInp = document.createElement('input');
    fileInp.type = 'file'; fileInp.accept = 'image/*'; fileInp.style.display = 'none';

    const drop = document.createElement('div');
    drop.className = 'scan-drop';
    drop.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
      <div style="font-weight:900;font-size:16px">ارفع صورة الفاتورة الورقية</div>
      <div style="font-weight:700;font-size:12.5px;margin-top:4px">اضغط للاختيار أو اسحب الصورة هنا — يدعم فواتير المذاخر العراقية</div>`;
    drop.onclick = () => fileInp.click();
    drop.ondragover = e => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = e => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) handle(e.dataTransfer.files[0]); };
    fileInp.onchange = () => { if (fileInp.files[0]) handle(fileInp.files[0]); };

    const stage = document.createElement('div');
    stage.style.marginTop = '16px';
    rootEl.append(drop, fileInp, stage);

    /* ★ صندوق وارد الجوال: الصور المرفوعة من تطبيق الجوال تصل هنا وتُقرأ تلقائياً */
    if (window._scanInboxOff) { try { window._scanInboxOff(); } catch (_) {} window._scanInboxOff = null; }
    (() => {
      let ref = null, stopped = false, seen = false, chain = Promise.resolve();
      const gone = () => { if (rootEl.isConnected) seen = true; return seen && !rootEl.isConnected; };
      const wait = ms => new Promise(r => setTimeout(r, ms));
      const stop = () => { stopped = true; if (ref) { try { ref.off(); } catch (_) {} ref = null; } };
      window._scanInboxOff = stop;
      const toFile = dataUrl => {
        const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || '');
        if (!m) return null;
        const bin = atob(m[2]), arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        return new File([arr], 'phone-scan.jpg', { type: m[1] });
      };
      const onPhoto = snap => { chain = chain.then(async () => {
        if (stopped) return;
        const r = snap.ref, v = snap.val() || {};
        if (v.status !== 'new') {
          if (Date.now() - (v.createdAt || 0) > 86400000) await r.remove();
          return;
        }
        const claim = await r.child('status').transaction(cur => cur === 'new' ? 'processing' : undefined);
        if (!claim.committed) return;
        const file = toFile(v.image);
        if (!file) { await r.update({ status: 'failed', image: null }); return; }
        while (!stopped && !gone() && stage.querySelector('.editable-table')) await wait(1500);
        if (stopped || gone()) { await r.child('status').set('new'); return; }
        toast('وصلت صورة من الجوال — جارٍ القراءة…');
        await handle(file);
        if (stage.querySelector('.editable-table')) await r.update({ status: 'done', image: null });
        else await r.update({ status: 'failed', image: null });
      }).catch(e => console.warn('scanInbox:', e)); };
      (async () => {
        while (!stopped && !gone() && !(typeof Sync !== 'undefined' && Sync.ready && Sync.db)) await wait(1500);
        if (stopped || gone()) return;
        ref = Sync.db.ref('pos/scanInbox');
        ref.on('child_added', onPhoto, e => { console.warn('scanInbox:', e); toast('تعذّر استقبال صور الجوال: ' + ((e && (e.code || e.message)) || 'خطأ'), 'r'); });
      })();
    })();

    async function handle(file) {
      const key = getKey();
      if (!key) {
        stage.innerHTML = `<div class="readonly-banner" style="margin-top:4px"><b>مفتاح Gemini غير موجود</b> — أدخله من: الإعدادات ← الماسح الذكي</div>`;
        return;
      }
      const pic = await prepImage(file);
      if (!pic) { stage.innerHTML = `<div class="readonly-banner"><b>تعذّر فتح ملف الصورة</b></div>`; return; }
      const { dataUrl, base64, mime } = pic;
      stage.innerHTML = `
        <div style="display:flex;gap:18px;flex-wrap:wrap">
          <img class="scan-preview" src="${dataUrl}">
          <div style="flex:1;min-width:260px;display:flex;flex-direction:column;gap:12px;justify-content:center">
            <div class="spinner"></div>
            <div style="text-align:center;font-weight:800;color:var(--muted)">Gemini يقرأ الفاتورة ويطابقها مع مخزنك…<br>عادةً 3–8 ثوانٍ</div>
          </div>
        </div>`;
      try {
        const data = await callGemini(base64, mime, key);
        const parsed = parseItems(data);
        /* ★ رأس الورقة: المذخر ورقم القائمة هما ما سيُملاه الماسح في قائمة الشراء — قابلان للتصحيح في الجدول */
        supplier = parsed.supplier; listNum = parsed.listNum;
        /* ★ بالترتيب: ترجمة اسم المذخر/الشركة → دمج البونص في سطر شرائه → مطابقة بمرحلتين على الاسم التجاري */
        parsed.items.forEach(it => { it.company = resolveCompany(it.company); });
        items = mergeBonus(parsed.items);
        items.forEach(it => autoLink(it));
        lastImage = dataUrl;
        if (!items.length) throw new Error('لم يُعثر على مواد في الفاتورة');
        drawTable(dataUrl);
      } catch (e) {
        stage.innerHTML = `<div class="readonly-banner" style="border-color:var(--red-soft);background:var(--red-ghost);color:var(--red)">
          <b>فشلت القراءة:</b> <span style="direction:ltr;unicode-bidi:plaintext;display:inline-block">${esc((e && e.message) || e)}</span><br>جرّب صورة أوضح وبإضاءة جيدة.</div>`;
      }
    }

        function drawTable(imgUrl) {
      stage.innerHTML = '';
      const wrap = document.createElement('div');
      wrap.style.display = 'flex'; wrap.style.flexDirection = 'column'; wrap.style.gap = '14px';

      const D_UNITS = ['mg', 'g', 'ml', 'mcg', 'IU', '%', 'mg/5ml', 'g/5ml', 'IU/ml', 'mcg/dose', 'ml/syringe'];
      const matched = items.filter(it => it.productId && !it.forceNew).length;
      const fresh = items.length - matched;
      const bLines = items.filter(it => (+it.bonusQty || 0) > 0).length;
      const head = document.createElement('div');
      head.style.cssText = 'display:flex;align-items:center;gap:12px;flex-wrap:wrap';
      head.innerHTML = `<span class="badge g">${items.length} مادة</span>
        <span class="badge b">مطابقة للمخزن: ${matched}</span>
        ${fresh ? `<span class="badge amber">جديدة: ${fresh}</span>` : ''}
        ${bLines ? `<span class="badge n">سطور فيها بونص: ${bLines}</span>` : ''}
        <span style="font-weight:700;color:var(--muted);font-size:12.5px">البحث أولاً بالاسم التجاري، ثم الشركة والجرعة والشكل تحسم — ✓ متطابق و✕ مختلف</span>`;

      /* ★ رأس الورقة كما قرأه الذكاء: المذخر ورقم القائمة — يصحّحهما هنا إن شاء، ويُملآن قائمة الشراء لحظة الاستيراد */
      const supI = h('input', { value: supplier, placeholder: 'اسم المذخر كما هو مطبوع فوق الورقة' });
      const lnI  = h('input', { value: listNum, placeholder: 'رقم القائمة', dir: 'ltr' });
      supI.addEventListener('input', () => { supplier = supI.value.trim(); });
      lnI.addEventListener('input', () => { listNum = lnI.value.trim(); });
      const headRow = h('div', { class: 'sc-headno' },
        h('label', {}, 'المذخر', supI),
        h('label', {}, 'رقم القائمة', lnI),
        h('span', {}, 'مقروءان من أعلى الصورة — يُنقلان تلقائياً إلى قائمة الشراء عند «استيراد إلى قائمة الشراء»'));

      const tbl = document.createElement('table');
      tbl.className = 'tbl editable-table';
      tbl.innerHTML = `<thead><tr><th>ت</th><th>اسم العلاج (إنكليزي LTR)</th><th>الجرعة</th><th>الشكل</th><th>الإكسباير</th><th>الشركة</th><th>الكمية</th><th>السعر المفرد</th><th>المجموع</th><th>الحالة</th><th></th></tr></thead>`;
      const tbody = document.createElement('tbody');

      /* علامة ✓/✕ لكل حقل حسمته المطابقة — الجرعة أو الشكل المختلف يرفض الصنف */
      const chipsOf = mk => {
        const one = (lab, v) => v === null || v === undefined || !mk ? '' : `<i class="sc-chip ${v ? 'ok' : 'no'}">${v ? '✓' : '✕'}${lab}</i>`;
        return `<span class="sc-chips">${one('الجرعة', mk && mk.dose)}${one('الشكل', mk && mk.form)}${one('الشركة', mk && mk.company)}</span>`;
      };

      items.forEach((it, i) => {
        const u = String(it.doseU || '');
        const opts = (u && !D_UNITS.includes(u) ? [u, ...D_UNITS] : D_UNITS)
          .map(x => `<option value="${esc(x)}"${x === u ? ' selected' : ''}>${esc(x)}</option>`).join('');
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="td-seq">${i + 1}</td>
          <td style="min-width:190px"><input data-f="name" dir="ltr" value="${esc(it.name)}">
            <input data-f="sci" dir="ltr" placeholder="الاسم العلمي (إن كتبه المذخر)" style="margin-top:4px;font-size:11.5px;color:var(--muted)" value="${esc(it.sci || '')}"></td>
          <td style="width:132px"><div class="sc-dose"><input data-f="doseV" dir="ltr" inputmode="decimal" placeholder="850" value="${esc(it.doseV || '')}">
            <select data-f="doseU" dir="ltr">${opts}</select></div></td>
          <td style="width:74px"><input data-f="form" dir="ltr" value="${esc(it.form || '')}"></td>
          <td style="width:88px"><input data-f="expiry" dir="ltr" placeholder="YYYY-MM" value="${esc(normExpiry(it.expiry) || it.expiry || '')}"></td>
          <td style="width:150px"><input data-f="company" value="${esc(it.company || '')}"></td>
          <td style="width:80px"><input data-f="qty" type="number" value="${it.qty}"></td>
          <td style="width:100px"><input data-f="price" type="number" value="${it.price}"></td>
          <td class="td-num td-total">${(it.qty * it.price || it.total).toLocaleString('en-US')}</td>
          <td class="td-match"><div class="sc-chips-box"></div>
            <label class="sc-bonus" title="عدد مجاني على هذا الشراء — يُسجَّل في دفتر البونص ولا يُضاف لعدد الشراء">بونص
              <input data-f="bonusQty" type="number" min="0" step="1" dir="ltr" value="${+it.bonusQty || 0}"></label></td>
          <td><button class="icon-btn del" title="حذف السطر"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg></button></td>`;

        const chipsTd = tr.querySelector('.sc-chips-box');
        /* خلية الحالة: الصنف المختار + علاماته + زرا التصحيح — و«عدّل الاختيار» عندما تتشابه أكثر من مادة */
        const paintMatch = () => {
          const m = (!it.forceNew && it.productId) ? findProd(it.productId) : null;
          chipsTd.innerHTML = '';
          const box = document.createElement('div');
          box.style.cssText = 'display:flex;gap:6px;align-items:center;flex-wrap:wrap';
          if (m) {
            const b = document.createElement('span'); b.className = 'badge g'; b.textContent = 'موجود: ' + m.brandName;
            const bn = document.createElement('button');
            bn.className = 'mini-btn red'; bn.style.cssText = 'flex:none;padding:5px 9px;font-size:11px';
            bn.textContent = 'ليس هو — أنشئ جديد';
            bn.onclick = () => { it.forceNew = true; it.productId = null; it.manual = false; drawTable(imgUrl); };
            box.append(b);
            if ((it.alts || []).length > 1) {
              const ba = document.createElement('button');
              ba.className = 'mini-btn blue'; ba.style.cssText = 'flex:none;padding:5px 9px;font-size:11px';
              ba.textContent = `عدّل الاختيار (${it.alts.length})`;
              ba.onclick = () => openPickProduct(it, () => { it.manual = true; drawTable(imgUrl); });
              box.append(ba);
            }
            box.append(bn);
            const cg = document.createElement('span'); cg.innerHTML = chipsOf(it.marks);
            chipsTd.append(box, cg);
          } else {
            const b = document.createElement('span'); b.className = 'badge amber';
            b.textContent = it.forceNew ? 'جديد (بقرارك) — سيُضاف للمخزن'
              : (it.alts || []).length > 1 ? 'أكثر من مادة بالاسم نفسه — حدّد الجرعة أو اختر' : 'جديد — سيُضاف للمخزن';
            const bp = document.createElement('button');
            bp.className = 'mini-btn blue'; bp.style.cssText = 'flex:none;padding:5px 9px;font-size:11px';
            bp.textContent = (it.alts || []).length > 1 ? 'اختر من المخزن' : 'موجود بالمخزن — اختره';
            bp.onclick = () => openPickProduct(it, () => { it.manual = true; drawTable(imgUrl); });
            box.append(b, bp);
            if ((it.alts || []).length > 1) {
              const bl = document.createElement('button');
              bl.className = 'mini-btn red'; bl.style.cssText = 'flex:none;padding:5px 9px;font-size:11px';
              bl.textContent = 'أنشئه جديداً';
              bl.onclick = () => { it.forceNew = true; it.productId = null; drawTable(imgUrl); };
              box.append(bl);
            }
            chipsTd.append(box);
          }
        };
        paintMatch();

        tr.querySelectorAll('input,select').forEach(inp => inp.addEventListener('input', () => {
          const f = inp.dataset.f;
          if (f === 'qty' || f === 'price' || f === 'bonusQty') it[f] = Math.max(0, +inp.value || 0);
          else it[f] = inp.value;
          if (f === 'doseV') it.doseV = String(inp.value).replace(/[^\d.]/g, '');
          if (f === 'doseU') it.doseU = String(inp.value).trim();
          if (f === 'doseV' || f === 'doseU') it.dose = String(it.doseV || '') + String(it.doseU || '');
          tr.children[8].textContent = (it.qty * it.price || it.total).toLocaleString('en-US');
          /* إعادة مطابقة حيّة عند كل تغيير في الاسم/الشركة/الجرعة/الشكل — إلا بقرار المستخدم */
          if ((f === 'name' || f === 'company' || f === 'doseV' || f === 'doseU' || f === 'form') && !it.forceNew && !it.manual) {
            it.company = resolveCompany(it.company);
            autoLink(it); paintMatch();
          }
        }));
        tr.querySelector('.icon-btn').onclick = () => { items.splice(i, 1); drawTable(imgUrl); };
        tbody.append(tr);
      });
      tbl.append(tbody);

      const foot = document.createElement('div');
      foot.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap';
      const img = document.createElement('img');
      img.className = 'scan-preview'; img.src = imgUrl; img.style.maxHeight = '120px';
      const importBtn = document.createElement('button');
      importBtn.className = 'btn g big';
      importBtn.innerHTML = 'استيراد إلى قائمة الشراء';
      importBtn.onclick = async () => {
        importBtn.disabled = true; importBtn.innerHTML = 'جارٍ التجهيز…';
        for (const it of items) {
          /* ★ الصنف الموجود لا يُنشَأ ولا يُعدَّل: الكمية ومتوسط التكلفة يحدثان في «حفظ قائمة الشراء» وحدها */
          let p = (!it.forceNew && it.productId) ? findProd(it.productId) : null;
          if (!p && !it.forceNew && !it.manual) p = autoLink(it);
          if (!p) p = await createProduct(it);
          it.productId = p.id;
        }
        const lots = lotsOf(items);
        const chosen = await askBonus(lots);
        onImport(items, { image: lastImage, supplier, listNum, bonusLots: chosen });
      };
      const newBtn = document.createElement('button');
      newBtn.className = 'btn n';
      newBtn.textContent = 'فاتورة أخرى';
      newBtn.onclick = () => { items = []; supplier = ''; listNum = ''; lastImage = ''; stage.innerHTML = ''; fileInp.value = ''; };
      const paper = document.createElement('span');
      paper.className = 'sc-paper';
      paper.textContent = lastImage ? 'صورة هذه القائمة تُلزم نسخة القائمة الورقية — تُحفظ مع القائمة وتُرفع للسحابة' : '';
      const sp = document.createElement('span');
      foot.append(importBtn, newBtn, sp, paper, img);
      sp.style.flex = 1;

      wrap.append(head, headRow, tbl, foot);
      stage.append(wrap);
    }

    /* ★ منتقي «موجود بالمخزن»: بحث حي بمحرك التطبيق نفسه واختيار بنقرة واحدة */
    function openPickProduct(it, onDone) {
      const inp = h('input', { placeholder: 'ابحث عن الصنف الموجود فعلاً…', value: it.name || '',
        style: { width: '100%', border: '1.5px solid var(--line)', borderRadius: '12px', padding: '11px 14px', fontWeight: 800, outline: 'none' } });
      const list = h('div', { style: { marginTop: '12px', maxHeight: '320px', overflowY: 'auto' } });
      const draw = () => {
        list.innerHTML = '';
        const res = searchProducts(inp.value);
        if (!res.length) { list.append(h('div', { class: 'empty-note' }, 'لا نتائج — جرّب كتابة جزء من الاسم')); return; }
        res.forEach(p => list.append(h('div', { class: 'inv-mini', onclick: () => {
          it.productId = p.id; it.forceNew = false;
          m.close(); onDone();
          toast(`رُبط بـ «${p.brandName}»`);
        } },
          h('div', { class: 'im-top' }, h('span', {}, p.brandName), h('b', {}, fmt(salePerUnit(p, p.units.length - 1)))),
          h('div', { class: 'im-sub' }, h('span', {}, p.company || ''), h('span', {}, `المخزون: ${fmt(p.stockBase || 0)}`))
        )));
      };
      inp.addEventListener('input', draw);
      const m = openModal({ title: 'اختيار الصنف الموجود من المخزن', icon: 'search', body: h('div', {}, inp, list) });
      draw(); inp.focus(); inp.select();
    }
  }

    return { mount, usableModels: async k => orderModels(await listModels(k)), normExpiry, resolveCompany };
})();
