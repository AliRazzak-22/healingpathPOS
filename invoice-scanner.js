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
{"supplier":"<supplier name if printed, else \"\">","items":[{"name":"","sci":"","dose":"","form":"","expiry":"","company":"","quantity":0,"unit_price":0,"total":0}]}
Strict rules for each item:
- name: the trade/brand name ONLY, in English (Latin) letters exactly as printed, Left-to-Right. Ignore every other text on the line. Never include Arabic text, company name, price or quantity inside name.
- dose: the strength ONLY if explicitly printed (e.g. "500mg", "250mg/5ml", "10%"). If not clearly printed use "".
- form: dosage form if printed — one of: Tab, Cap, Amp, Vial, Syrup, Susp, Drops, Cream, Oint, Gel, Supp, Sachet, Spray, Inhaler, Patch, Infusion. Otherwise "".
- sci: the scientific (generic) name if the supplier printed it, else "".
- expiry: the expiry date printed for this line, normalized to "YYYY-MM". If missing or unreadable use "".
- company: manufacturer/brand company if printed, else "".
- quantity, unit_price, total: plain numbers only (no currency symbols). If unreadable use 0.
- Ignore headers, invoice totals, taxes, discounts and any non-product line.
- Output must start with { and end with } and nothing else.`;

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

    /* ★ البحث في المخزن أولاً — بمحرك بحث التطبيق نفسه (arTokens + _scoreProduct)
     فالتطابق أصبح مطابقاً تماماً لما يعطيه البحث اليدوي: لا «موجود» زائف ولا «غير موجود» زائف */
  function bestMatch(name, company) {
    const n = norm(name);
    if (!n) return null;
    const live = state.products.filter(p => !p.deleted);
    let m = live.find(p => (p.barcodes || []).some(b => norm(b) === n));
    if (m) return m;
    m = live.find(p => norm(p.brandName) === n);
    if (m) return m;
    m = live.find(p => norm(p.scientificName) && norm(p.scientificName) === n);
    if (m) return m;
    const qt = arTokens(name);
    let best = null, bestScore = 0;
    live.forEach(p => {
      const s = (qt.length ? _scoreProduct(p, qt, true) : 0) + companyBonus(p, company);
      if (s > bestScore) { bestScore = s; best = p; }
    });
    return bestScore >= 35 ? best : null; /* عتبة محسوبة: تقبل الخطأ الإملائي الواحد وترفض التخمين */
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

    /* إنشاء صنف جديد — الاسم بصيغة ملزمة: التجاري - الجرعة - الشكل (إنكليزي LTR فقط)،
     وداخلياً يحفظ: الاسم العلمي + الشكل + الجرعة + الإكسباير المقروء من ورقة المذخر */
  async function createProduct(it) {
    const price = +it.price || 0;
    const profit = +(state.settings.profitPct ?? 30);
    const dose = String(it.dose || '').trim();
    let form = String(it.form || '').trim();
    if (form && !FORMS.includes(form)) FORMS.push(form); // شكل جديد يُضاف لقائمة الأشكال تلقائياً
    const p = {
      id: uid(),
      brandName: [String(it.name || '').trim(), dose, form].filter(Boolean).join(' '),
      scientificName: String(it.sci || '').trim(),
      barcodes: [genBarcode()],
      form: form || 'Tab', dose, expiry: normExpiry(it.expiry), featured: false,
      company: resolveCompany(it.company), country: '',
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

  /* تصغير الصورة وتحويلها JPEG قبل الإرسال: أسرع، ويحلّ مشاكل الصور الضخمة وHEIC */
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
      img.onload = () => {
        try {
          const k = Math.min(1, 2200 / Math.max(img.naturalWidth, img.naturalHeight));
          const c = document.createElement('canvas');
          c.width = Math.round(img.naturalWidth * k); c.height = Math.round(img.naturalHeight * k);
          const ctx = c.getContext('2d'); ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, c.width, c.height); ctx.drawImage(img, 0, 0, c.width, c.height);
          const dataUrl = c.toDataURL('image/jpeg', 0.88);
          URL.revokeObjectURL(url);
          resolve({ dataUrl, base64: dataUrl.split(',')[1], mime: 'image/jpeg' });
        } catch (_) { URL.revokeObjectURL(url); raw(); }
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
        const items = (obj.items || []).map(x => ({
      name: String(x.name || '').trim(),
      sci: String(x.sci || x.scientific || '').trim(),
      dose: String(x.dose || '').trim(),
      form: String(x.form || '').trim(),
      expiry: String(x.expiry || '').trim(),
      company: String(x.company || '').trim(),
      qty: +x.quantity || +x.qty || 0,
      price: +x.unit_price || +x.price || 0,
      total: +x.total || 0,
    })).filter(x => x.name);
    return { supplier: String(obj.supplier || '').trim(), items };
  }

  function mount(rootEl, { getKey, onImport }) {
    let items = [], supplier = '';
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
        supplier = parsed.supplier; items = parsed.items;
        if (!items.length) throw new Error('لم يُعثر على مواد في الفاتورة');
                /* الشركة تُترجم أولاً لاسمها المسجّل (عربي/إنكليزي) ثم تُطابَخ الأصناف */
        items.forEach(it => {
          it.company = resolveCompany(it.company);
          const m = bestMatch(it.name, it.company);
          it.productId = m ? m.id : null;
        });
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

      const matched = items.filter(it => it.productId && !it.forceNew).length;
      const fresh = items.length - matched;
      const head = document.createElement('div');
      head.style.cssText = 'display:flex;align-items:center;gap:12px;flex-wrap:wrap';
      head.innerHTML = `<span class="badge g">${items.length} مادة</span>
        <span class="badge b">مطابقة للمخزن: ${matched}</span>
        ${fresh ? `<span class="badge amber">جديدة: ${fresh}</span>` : ''}
        ${supplier ? `<span class="badge n">المذخر: ${esc(supplier)}</span>` : ''}
        <span style="font-weight:700;color:var(--muted);font-size:12.5px">راجع وعدّل — زرّا «موجود / ليس هو» يصححان أي مطابقة خاطئة فوراً</span>`;

      const tbl = document.createElement('table');
      tbl.className = 'tbl editable-table';
      tbl.innerHTML = `<thead><tr><th>ت</th><th>اسم العلاج (إنكليزي LTR)</th><th>الجرعة</th><th>الشكل</th><th>الإكسباير</th><th>الشركة</th><th>الكمية</th><th>السعر المفرد</th><th>المجموع</th><th>الحالة</th><th></th></tr></thead>`;
      const tbody = document.createElement('tbody');

      items.forEach((it, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td class="td-seq">${i + 1}</td>
          <td style="min-width:190px"><input data-f="name" dir="ltr" value="${esc(it.name)}">
            <input data-f="sci" dir="ltr" placeholder="الاسم العلمي (إن كتبه المذخر)" style="margin-top:4px;font-size:11.5px;color:var(--muted)" value="${esc(it.sci || '')}"></td>
          <td style="width:74px"><input data-f="dose" dir="ltr" value="${esc(it.dose || '')}"></td>
          <td style="width:74px"><input data-f="form" dir="ltr" value="${esc(it.form || '')}"></td>
          <td style="width:88px"><input data-f="expiry" dir="ltr" placeholder="YYYY-MM" value="${esc(normExpiry(it.expiry) || it.expiry || '')}"></td>
          <td style="width:150px"><input data-f="company" value="${esc(it.company || '')}"></td>
          <td style="width:80px"><input data-f="qty" type="number" value="${it.qty}"></td>
          <td style="width:100px"><input data-f="price" type="number" value="${it.price}"></td>
          <td class="td-num td-total">${(it.qty * it.price || it.total).toLocaleString('en-US')}</td>
          <td class="td-match"></td>
          <td><button class="icon-btn del" title="حذف السطر"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg></button></td>`;

        const matchTd = tr.querySelector('.td-match');
        matchTd.style.cssText = 'min-width:170px';
        /* خلية الحالة + زرا التصحيح: «موجود بالمخزن — اختره» و«ليس هو — أنشئ جديد» */
        const paintMatch = () => {
          const m = (!it.forceNew && it.productId) ? findProd(it.productId) : null;
          matchTd.innerHTML = '';
          const box = document.createElement('div');
          box.style.cssText = 'display:flex;gap:6px;align-items:center;flex-wrap:wrap';
          if (m) {
            const b = document.createElement('span'); b.className = 'badge g'; b.textContent = 'موجود: ' + m.brandName;
            const bn = document.createElement('button');
            bn.className = 'mini-btn red'; bn.style.cssText = 'flex:none;padding:5px 9px;font-size:11px';
            bn.textContent = 'ليس هو — أنشئ جديد';
            bn.onclick = () => { it.forceNew = true; it.productId = null; drawTable(imgUrl); };
            box.append(b, bn);
          } else {
            const b = document.createElement('span'); b.className = 'badge amber';
            b.textContent = it.forceNew ? 'جديد (بقرارك) — سيُضاف للمخزن' : 'جديد — سيُضاف للمخزن';
            const bp = document.createElement('button');
            bp.className = 'mini-btn blue'; bp.style.cssText = 'flex:none;padding:5px 9px;font-size:11px';
            bp.textContent = 'موجود بالمخزن — اختره';
            bp.onclick = () => openPickProduct(it, () => drawTable(imgUrl));
            box.append(b, bp);
          }
          matchTd.append(box);
        };
        paintMatch();

        tr.querySelectorAll('input').forEach(inp => inp.addEventListener('input', () => {
          const f = inp.dataset.f;
          if (f === 'qty' || f === 'price') it[f] = (+inp.value || 0);
          else it[f] = inp.value;
          tr.children[8].textContent = (it.qty * it.price || it.total).toLocaleString('en-US');
          /* إعادة المطابقة الحيّة عند تغيير الاسم/الشركة — إلا إذا قرر المستخدم «ليس هو» */
          if ((f === 'name' || f === 'company') && !it.forceNew) {
            const mm = bestMatch(it.name, resolveCompany(it.company));
            it.productId = mm ? mm.id : null;
            paintMatch();
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
        importBtn.disabled = true; importBtn.innerHTML = 'جارٍ الإنشاء والاستيراد…';
        for (const it of items) {
          /* ★ لا إنشاء إلا عند غياب المطابقة أو عند قرار المستخدم «ليس هو» */
          let p = (!it.forceNew && it.productId) ? findProd(it.productId) : null;
          if (!p && !it.forceNew) p = bestMatch(it.name, it.company);
          if (!p) p = await createProduct(it);
          else {
            /* الإكسباير المقروء من ورقة المذخر يُعتمد للصنف الموجود إن كان بلا تاريخ */
            const ex = normExpiry(it.expiry);
            if (ex && !p.expiry) { p.expiry = ex; await save('products', p); }
          }
          it.productId = p.id;
        }
        onImport(items);
      };
      const newBtn = document.createElement('button');
      newBtn.className = 'btn n';
      newBtn.textContent = 'فاتورة أخرى';
      newBtn.onclick = () => { items = []; supplier = ''; stage.innerHTML = ''; fileInp.value = ''; };
      foot.append(importBtn, newBtn, document.createElement('span'), img);
      foot.children[2].style.flex = 1;

      wrap.append(head, tbl, foot);
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
