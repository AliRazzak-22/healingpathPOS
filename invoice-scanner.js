/* ═══════════════════════════════════════════════════════════════
   الماسح الذكي — قراءة الفواتير الورقية بالصور (Gemini API)
   • يرفع الصورة → يستخرج (الاسم، الشركة، الكمية، السعر) بصيغة JSON
   • يبحث في مخزن الصيدلية أولاً ويمنع إنشاء أي صنف مكرر
   • الأصناف غير الموجودة تُنشأ بنفس أسلوب أصنافك (براند/شركة/شكل/وحدة/سعر + باركود مولّد)
   • جدول مراجعة قابل للتعديل → استيراد مباشر إلى قائمة الشراء
   ═══════════════════════════════════════════════════════════════ */
window.InvoiceScanner = (() => {

  
  const PROMPT = `You are an expert pharmaceutical invoice OCR system for an Iraqi pharmacy.
Analyze this invoice image and extract EVERY line item.
Return ONLY a JSON object (no markdown, no explanation) in this exact shape:
{"supplier":"<distributor/supplier company name if printed, else \"\">","items":[{"name":"<drug brand name exactly as printed>","company":"<manufacturer company if printed, else \"\">","quantity":<number>,"unit_price":<number>,"total":<number>}]}
Rules:
- Keep drug names exactly as printed (Arabic or English), do not translate or invent.
- quantity, unit_price, total must be plain numbers (no currency symbols).
- If a value is unreadable use 0, and use "" for unknown text.
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

  /* ★ البحث في المخزن أولاً — يمنع إنشاء أي نسخة مكررة */
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
    m = live.find(p => { const b = norm(p.brandName); return b && (b.includes(n) || n.includes(b)); });
    if (m) return m;
    /* مطابقة ضبابية عالية + تفضيل نفس الشركة */
    let best = null, bestScore = 0;
    const cn = norm(company);
    live.forEach(p => {
      let s = sim(n, norm(p.brandName));
      if (cn && norm(p.company) && (norm(p.company).includes(cn) || cn.includes(norm(p.company)))) s += 0.08;
      if (s > bestScore) { bestScore = s; best = p; }
    });
    return bestScore >= 0.72 ? best : null;
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

  /* إنشاء صنف جديد بنفس أسلوب أصناف المخزن */
  async function createProduct(it) {
    const price = +it.price || 0;
    const profit = +(state.settings.profitPct ?? 30);
    const p = {
      id: uid(),
      brandName: String(it.name || '').trim(),
      scientificName: '',
      barcodes: [genBarcode()],
      form: 'Tab', dose: '', expiry: '', featured: false,
      company: String(it.company || '').trim(), country: '',
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
        items.forEach(it => { const m = bestMatch(it.name, it.company); it.productId = m ? m.id : null; });
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

      const matched = items.filter(it => it.productId).length;
      const fresh = items.length - matched;
      const head = document.createElement('div');
      head.style.cssText = 'display:flex;align-items:center;gap:12px;flex-wrap:wrap';
      head.innerHTML = `<span class="badge g">${items.length} مادة</span>
        <span class="badge b">مطابقة للمخزن: ${matched}</span>
        ${fresh ? `<span class="badge amber">جديدة: ${fresh}</span>` : ''}
        ${supplier ? `<span class="badge n">المذخر: ${supplier}</span>` : ''}
        <span style="font-weight:700;color:var(--muted);font-size:12.5px">راجع الأسماء والكميات وعدّل أي خطأ قبل الاستيراد</span>`;

      const tbl = document.createElement('table');
      tbl.className = 'tbl editable-table';
      tbl.innerHTML = `<thead><tr><th>ت</th><th>اسم العلاج</th><th>الشركة</th><th>الكمية</th><th>السعر المفرد</th><th>المجموع</th><th>الحالة</th><th></th></tr></thead>`;
      const tbody = document.createElement('tbody');

      items.forEach((it, i) => {
        const tr = document.createElement('tr');
        const m = it.productId ? findProd(it.productId) : null;
        tr.innerHTML = `
          <td class="td-seq">${i + 1}</td>
          <td><input data-f="name" value="${String(it.name).replace(/"/g, '&quot;')}"></td>
          <td style="width:170px"><input data-f="company" value="${String(it.company || '').replace(/"/g, '&quot;')}"></td>
          <td style="width:90px"><input data-f="qty" type="number" value="${it.qty}"></td>
          <td style="width:110px"><input data-f="price" type="number" value="${it.price}"></td>
          <td class="td-num td-total">${(it.qty * it.price || it.total).toLocaleString('en-US')}</td>
          <td class="td-match">${m
            ? `<span class="badge g">موجود: ${m.brandName}</span>`
            : `<span class="badge amber">جديد — سيُضاف للمخزن</span>`}</td>
          <td><button class="icon-btn del" title="حذف السطر"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg></button></td>`;
        tr.querySelectorAll('input').forEach(inp => inp.addEventListener('input', () => {
          const f = inp.dataset.f;
          it[f] = (f === 'qty' || f === 'price') ? (+inp.value || 0) : inp.value;
          tr.children[5].textContent = (it.qty * it.price || it.total).toLocaleString('en-US');
          /* إعادة المطابقة الحيّة عند تغيير الاسم أو الشركة */
          const mm = bestMatch(it.name, it.company);
          it.productId = mm ? mm.id : null;
          tr.querySelector('.td-match').innerHTML = mm
            ? `<span class="badge g">موجود: ${esc(mm.brandName)}</span>`
            : `<span class="badge amber">جديد — سيُضاف للمخزن</span>`;
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
          /* ★ لا إنشاء إلا عند غياب أي مطابقة — بحث مخزني أولاً دائماً */
          let p = it.productId ? findProd(it.productId) : null;
          if (!p) p = bestMatch(it.name, it.company);
          if (!p) p = await createProduct(it);
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
  }

    return { mount, usableModels: async k => orderModels(await listModels(k)) };
})();
