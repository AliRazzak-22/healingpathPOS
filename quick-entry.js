/* ═══════════════════════════════════════════════════════════════
   الإدخال السريع — صورة واحدة لعشرات العلبات ← صفوف كبيرة ← حفظ جماعي
   • قراءة أولى بـ Gemini، ثم قراءة ثانية بمزوّد مختلف، ثم «قاضٍ» يقارن ويحسم ويبحث في الويب عن التعبئة
   • كل صنف = سطر واحد وكل خانة = عمود: عشرون صنفاً تُشتغل من صفحة واحدة بأسهم الكيبورد (فوق/تحت/يمين/يسار)
   • لا يدخل المخزن أي صنف قبل الضغط على «حفظ» وتأكيد ذلك — ومسودة محلية تحمي من الإغلاق بالخطأ
   • الصور لا تُخزَّن داخل سجل الصنف أبداً، والمفاتيح لا تخرج من نداء المزوّد إلى أي مكان آخر
   ═══════════════════════════════════════════════════════════════ */
window.QuickEntry = (() => {
  const IS = () => window.InvoiceScanner;
  const S = x => String(x == null ? '' : x).trim();
  const clean = (x, n) => S(x).replace(/[\x00-\x1F\x7F\u200B-\u200F\u202A-\u202E\uFEFF]/g, ' ').replace(/\s+/g, ' ').slice(0, n || 120);
  const int = (v, hi) => { const n = Math.round(parseFloat(v)); return isFinite(n) && n > 0 ? Math.min(hi || 99999, n) : 0; };
  const r2 = n => Math.round((+n || 0) * 100) / 100;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const nowYM = () => { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0'); };
  const mkAbort = () => { const e = new Error('أُلغي التحليل'); e.cancelled = true; return e; };

  const GB = 'https://generativelanguage.googleapis.com/v1beta';
  const BASE = { openai: 'https://api.openai.com/v1', xai: 'https://api.x.ai/v1', groq: 'https://api.groq.com/openai/v1', deepseek: 'https://api.deepseek.com', mistral: 'https://api.mistral.ai/v1', perplexity: 'https://api.perplexity.ai', openrouter: 'https://openrouter.ai/api/v1' };

  /* أي النماذج تقرأ الصور فعلاً (deepseek نصي فقط فلا يدخل القائمة) */
  const VISION = {
    gemini: n => /^gemini-/.test(n) && !/(embedding|tts|live|robotics|computer|aqa|image-|gemma)/.test(n),
    anthropic: n => /^claude-/.test(n),
    openai: n => /^(gpt-4o|gpt-4\.1|gpt-5|gpt-4-)/.test(n) && !/(audio|realtime|transcribe|image|instruct|-all)/.test(n),
    xai: n => /^grok-/.test(n) && !/(imagine|video)/.test(n),
    groq: n => /(llama-4|vision)/.test(n),
    mistral: n => /(pixtral|vision)/.test(n),
    perplexity: n => /sonar/.test(n),
    openrouter: n => /(vision|multimodal|llama-4|gpt-4o|gpt-4\.1|claude|gemini|pixtral)/.test(n),
  };

  const FORM_MAP = { tab: 'Tab', tabs: 'Tab', tablet: 'Tab', tablets: 'Tab', cap: 'Cap', caps: 'Cap', capsule: 'Cap', capsules: 'Cap',
    amp: 'Amp', ampul: 'Amp', ampoule: 'Amp', vial: 'Vial', gum: 'Gum', syrup: 'Syrup', sirup: 'Syrup', syp: 'Syrup',
    susp: 'Susp', suspension: 'Susp', supp: 'Supp', suppository: 'Supp', drops: 'Drops', drop: 'Drops', cream: 'Cream',
    oint: 'Oint', ointment: 'Oint', gel: 'Gel', sachet: 'Sachet', spray: 'Spray', inhaler: 'Inhaler', patch: 'Patch', infusion: 'Infusion' };
  const PACK_MAP = { carton: 'كرتون', box: 'علبة', packet: 'باكيت', pack: 'باكيت', strip: 'شريط', blister: 'شريط', wallet: 'شريط',
    bottle: 'قنينة', tube: 'أنبوب', jar: 'علبة', tin: 'علبة', bag: 'كيس', ampoule: 'أمبول', vial: 'فيال', can: 'علبة' };

  const FLAG_LABEL = { name: 'الاسم', sci: 'العلمي', company: 'الشركة', dose: 'الجرعة', form: 'الشكل', pack: 'التعبئة', barcode: 'الباركود', expiry: 'الإكسباير' };
  const COLS = [
    { k: '#', t: '#', w: '54px' },
    { k: 'pic', t: 'الصورة', w: '78px' },
    { k: 'und', t: 'ما فهمناه من العلبة', w: '330px' },
    { k: 'pack', t: 'تأكيد التعبئة', w: '250px', fill: 1 },
    { k: 'factor', t: '= عدد الصغرى', w: '120px' },
    { k: 'stock', t: 'الجرد بالوحدة الصغيرة', w: '140px', fill: 1 },
    { k: 'buyTop', t: 'سعر شراء الوحدة الكبيرة', w: '150px', fill: 1 },
    { k: 'saleBase', t: 'سعر بيع الوحدة الصغيرة', w: '150px', fill: 1 },
    { k: 'barcode', t: 'الباركود', w: '170px', fill: 1 },
    { k: 'expiry', t: 'الإكسباير', w: '150px', fill: 1 },
    { k: 'stat', t: 'الحالة', w: '190px' },
  ];

  let st = null, stage = null, els = {}, cssDone = false, localEnt = null, localModel = null;

  /* ───────────────────────── التنسيق (يُحقن هنا كي لا يتلمس style.css) ───────────────────────── */
  function css() {
    if (cssDone) return; cssDone = true;
    const el = document.createElement('style'); el.id = 'qe-css';
    el.textContent = `
.qe-stage{position:absolute;inset:0;pointer-events:all;background:var(--bg);display:flex;flex-direction:column;animation:fadeIn .18s ease}
.qe-head{flex:none;display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 18px;background:var(--white);border-bottom:1px solid var(--line);box-shadow:var(--shadow-sm)}
.qe-title{display:flex;align-items:center;gap:10px;font-weight:900;font-size:18px}
.qe-title svg{width:24px;height:24px;color:var(--green)}
.qe-title small{display:block;font-size:11.5px;color:var(--muted);font-weight:700}
.qe-chips{display:flex;gap:7px;flex-wrap:wrap}
.qe-chip{border:1px solid var(--line);background:var(--bg);border-radius:999px;padding:4px 12px;font-size:12.5px;font-weight:900;color:var(--ink-2)}
.qe-chip b{color:var(--green)}
.qe-chip.warn{background:#fef3c7;border-color:#fcd34d;color:#92400e}
.qe-sp{flex:1}
.qe-opt{display:flex;align-items:center;gap:6px;font-size:12.5px;font-weight:800;color:var(--muted);cursor:pointer;user-select:none}
.qe-opt input{width:16px;height:16px;accent-color:var(--green);cursor:pointer}
.qe-strip{flex:none;display:flex;gap:9px;align-items:center;padding:9px 18px;background:var(--green-ghost);border-bottom:1px solid var(--line);overflow-x:auto}
.qe-photo{position:relative;flex:none;width:78px;height:60px;border-radius:11px;overflow:hidden;border:2px solid var(--line);background:var(--white);cursor:zoom-in}
.qe-photo.used{border-color:var(--green)}
.qe-photo img{width:100%;height:100%;object-fit:cover;display:block}
.qe-photo .ph-x{position:absolute;top:2px;left:2px;width:19px;height:19px;border-radius:7px;background:rgba(15,23,42,.62);color:#fff;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:900}
.qe-photo .ph-n{position:absolute;bottom:2px;right:3px;background:rgba(15,23,42,.62);color:#fff;border-radius:7px;padding:0 5px;font-size:10.5px;font-weight:900}
.qe-strip .qe-tip{font-size:12px;font-weight:800;color:var(--muted);white-space:nowrap}
.qe-body{flex:1;min-height:0;display:flex;flex-direction:column;padding:14px 18px 0;gap:12px;overflow:hidden}
.qe-bar{flex:none;display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.qe-bar input,.qe-bar select{border:1.5px solid var(--line);border-radius:11px;padding:8px 11px;font-weight:800;background:var(--white);outline:none}
.qe-drop{flex:1;min-height:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;border:2.5px dashed var(--line-2);border-radius:24px;background:var(--white);text-align:center;padding:26px;overflow:auto}
.qe-drop.hot{border-color:var(--green);background:var(--green-ghost)}
.qe-drop h2{font-size:24px;font-weight:900}
.qe-drop p{font-weight:700;color:var(--muted);line-height:2;max-width:760px;font-size:14px}
.qe-rules{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;max-width:980px;width:100%}
.qe-rule{border:1px solid var(--line);border-radius:14px;padding:11px 13px;text-align:right;background:var(--bg);font-weight:800;font-size:13px;line-height:1.9}
.qe-rule b{color:var(--green)}
.qe-grid{flex:1;min-height:0;display:flex;flex-direction:column;background:var(--white);border:1px solid var(--line);border-radius:18px;overflow:hidden;box-shadow:var(--shadow-sm)}
.qe-tbl{min-width:1750px}
.qe-tbl td{padding:9px 8px;vertical-align:top}
.qe-tbl tr.qe-done td{background:var(--green-ghost)}
.qe-tbl tr.qe-todo td:first-child{box-shadow:inset 4px 0 0 #f59e0b}
.qe-in{width:100%;min-height:38px;border:1.5px solid var(--line);border-radius:10px;padding:6px 9px;font-weight:800;font-size:14.5px;background:var(--white);outline:none;transition:border var(--tr),box-shadow var(--tr)}
.qe-in:focus{border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-soft)}
.qe-in.bad{border-color:var(--red);box-shadow:0 0 0 3px var(--red-soft)}
select.qe-in{padding:5px 7px}
.qe-und{display:flex;flex-direction:column;gap:3px;font-size:12.5px;line-height:1.55}
.qe-und .u1{font-size:15px;font-weight:900;color:var(--ink)}
.qe-und .u1 em{font-style:normal;color:var(--blue)}
.qe-und .u2{color:var(--ink-2);font-weight:700}
.qe-und .u3{color:var(--muted);font-weight:800}
.qe-badges{display:flex;gap:4px;flex-wrap:wrap;margin-top:3px}
.qb{border-radius:7px;padding:1px 7px;font-size:11px;font-weight:900}
.qb.ok{background:var(--green-soft);color:#047857}
.qb.fix{background:#e0e7ff;color:#3730a3}
.qb.ask{background:#fef3c7;color:#92400e}
.qe-link{margin-top:4px;font-weight:900;font-size:12px}
.qe-link.ex{color:var(--blue)}
.qe-link.new{color:#7c3aed}
.qe-pack{display:flex;flex-direction:column;gap:5px}
.qe-prow{display:flex;align-items:center;gap:4px}
.qe-prow .qe-in{min-height:34px}
.qe-prow .pn{width:62px;flex:none}
.qe-prow .pu{flex:1;min-width:72px}
.qe-prow .par{font-weight:900;color:var(--muted);font-size:12px;flex:none}
.qe-fact{font-weight:900;font-size:13.5px;color:var(--ink-2);line-height:1.6}
.qe-fact small{display:block;color:var(--muted);font-weight:800;font-size:11px}
.qe-hint{font-size:11px;font-weight:800;color:var(--muted);margin-top:3px}
.qe-hint.pos{color:var(--green)}
.qe-hint.neg{color:var(--red)}
.qe-thumb{width:62px;height:48px;border-radius:9px;border:1px solid var(--line);overflow:hidden;background:var(--bg);cursor:zoom-in;display:block}
.qe-thumb img{width:100%;height:100%;object-fit:cover}
.qe-mini{border:1px solid var(--line);background:var(--white);border-radius:9px;padding:3px 9px;font-size:11.5px;font-weight:900;color:var(--ink-2);transition:all var(--tr)}
.qe-mini:hover{border-color:var(--green);color:var(--green)}
.qe-mini.r{color:var(--red)}.qe-mini.r:hover{border-color:var(--red)}
.qe-btns{display:flex;gap:5px;flex-wrap:wrap;margin-top:5px}
.qe-stat{display:flex;flex-direction:column;gap:4px;align-items:flex-start}
.qe-seq{font-weight:900;color:var(--faint);font-size:13px}
.qe-foot{flex:none;display:flex;align-items:center;gap:12px;padding:8px 18px 12px;font-weight:800;font-size:13px;color:var(--muted)}
.qe-prog{display:flex;align-items:center;gap:9px;font-weight:900;color:var(--blue)}
.qe-prog .sp{width:15px;height:15px;border:2.5px solid var(--blue-soft);border-top-color:var(--blue);border-radius:50%;animation:qeSpin .8s linear infinite}
@keyframes qeSpin{to{transform:rotate(360deg)}}
.qe-detail td{background:var(--bg)}
.qe-dbox{display:flex;flex-direction:column;gap:7px;font-size:13px;font-weight:700;line-height:1.9}
.qe-dbox .dk{color:var(--muted);font-weight:900}
.qe-dbox .dv{color:var(--ink);font-weight:800}
.qe-imgbig{max-width:100%;max-height:72vh;border-radius:14px;display:block;margin:0 auto}
.qe-errlist{display:flex;flex-direction:column;gap:8px}
.qe-errrow{border:1px solid var(--red-soft);background:var(--red-ghost);border-radius:12px;padding:9px 12px;font-weight:800;font-size:13px;line-height:1.9}
.qe-errrow b{color:var(--red);font-size:13.5px}
.qe-errrow button{margin-top:5px}
.qe-list{display:flex;flex-direction:column;gap:7px;max-height:56vh;overflow:auto}
.qe-li{border:1px solid var(--line);border-radius:12px;padding:9px 12px;font-weight:800;cursor:pointer;text-align:right}
.qe-li:hover{border-color:var(--green);background:var(--green-ghost)}
.qe-li small{display:block;color:var(--muted);font-weight:700}
html[data-theme="dark"] .qe-chip.ask,html[data-theme="dark"] .qb.ask,html[data-theme="dark"] .qe-chip.warn{background:#3a2d07;color:#fcd34d}
html[data-theme="dark"] .qb.ok{background:#06371f;color:#4ade80}
html[data-theme="dark"] .qb.fix{background:#1e1b4b;color:#c7d2fe}
html[data-theme="dark"] .qe-chip,html[data-theme="dark"] .qe-drop,html[data-theme="dark"] .qe-grid,html[data-theme="dark"] .qe-in,html[data-theme="dark"] .qe-bar input,html[data-theme="dark"] .qe-bar select,html[data-theme="dark"] .qe-mini,html[data-theme="dark"] .qe-head{background:var(--white)}
`;
    document.head.append(el);
  }

  /* ───────────────────────── الأوامر: بناء الواجهة ───────────────────────── */
  function btn(label, ic, cls, fn) {
    return h('button', { class: 'btn ' + (cls || 'n'), onclick: fn }, ic ? h('span', { html: icon(ic) }) : null, label);
  }

  function build() {
    els = {};
    stage = h('div', { class: 'qe-stage', tabindex: '-1' });

    els.chips = h('div', { class: 'qe-chips' });
    els.optDouble = chk('تدقيق بمزوّد ثانٍ', 'double');
    els.optWeb = chk('تأكيد التعبئة من الويب', 'web');
    els.head = h('div', { class: 'qe-head' },
      h('div', { class: 'qe-title' }, h('span', { html: icon('pill') }),
        h('div', {}, 'الإدخال السريع', h('small', {}, 'صوّر علبات الدواء مرة واحدة ← جدول ضخم ← حفظ دفعة واحدة'))),
      els.chips,
      h('div', { class: 'qe-sp' }),
      els.optDouble, els.optWeb,
      btn('صورة', 'camera', 'b', () => els.file.click()),
      btn('تحليل الصور', 'refresh', 'g', () => run()),
      btn('حفظ الكل', 'check', 'g', () => saveAll()),
      btn('ملصقات باركود', 'print', 'n', () => askPrint()),
      btn('مسح الكل', 'trash', 'n', () => clearAll()),
      btn('إغلاق', 'close', 'n', () => requestClose()));

    els.file = h('input', { type: 'file', accept: 'image/*', multiple: 'true', style: { display: 'none' } });
    els.file.addEventListener('change', () => { addFiles(els.file.files); els.file.value = ''; });

    els.strip = h('div', { class: 'qe-strip', style: { display: 'none' } });
    els.body = h('div', { class: 'qe-body' });
    els.prog = h('div', { class: 'qe-prog' });
    els.foot = h('div', { class: 'qe-foot' },
      els.prog,
      h('div', { class: 'qe-sp' }),
      h('span', {}, 'الأسهم ← ↑ ↓ → بين الخلايا والصفوف · Ctrl+S حفظ الكل · Esc إغلاق'));

    stage.append(els.head, els.file, els.strip, els.body, els.foot);
    stage.addEventListener('keydown', onStageKey);
  }
  function chk(label, key) {
    const i = h('input', { type: 'checkbox', checked: st.opts[key] });
    i.addEventListener('change', () => { st.opts[key] = i.checked; saveDraft(); });
    return h('label', { class: 'qe-opt' }, i, label);
  }

  function onStageKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); requestClose(); return; }
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 's' || e.key === 'S' || e.code === 'KeyS')) { e.preventDefault(); e.stopPropagation(); saveAll(); }
  }

  /* الشريط العلوي: عدادات حيّة */
  function chips() {
    if (!stage || !els.chips) return;
    const unsaved = st.rows.filter(r => !r.saved).length, saved = st.rows.length - unsaved;
    const todo = st.rows.filter(r => !r.saved && askCount(r) > 0).length;
    els.chips.innerHTML = '';
    [...h('div', {},
      h('span', { class: 'qe-chip' }, 'صور ', h('b', {}, String(st.photos.length))),
      h('span', { class: 'qe-chip' }, 'أصناف ', h('b', {}, String(st.rows.length))),
      h('span', { class: 'qe-chip' }, 'محفوظ ', h('b', {}, String(saved))),
      h('span', { class: 'qe-chip' }, 'بانتظار الحفظ ', h('b', {}, String(unsaved))),
      todo ? h('span', { class: 'qe-chip warn' }, 'تحتاج مراجعة ', h('b', {}, String(todo))) : null,
      st.calls ? h('span', { class: 'qe-chip' }, 'تحليلات الذكاء ', h('b', {}, String(st.calls))) : null).children].forEach(n => els.chips.append(n));
  }
  function prog(msg) {
    if (!els.prog) return;
    els.prog.innerHTML = '';
    if (!msg) { els.prog.append(h('span', { style: { color: 'var(--muted)' } }, st.rows.length ? 'جاهز — راجع الأعمدة ثم احفظ' : '')); return; }
    els.prog.append(h('span', { class: 'sp' }), msg);
  }

  /* ───────────────────────── الصور ───────────────────────── */
  function drawStrip() {
    if (!st || !els.strip) return;
    els.strip.innerHTML = '';
    if (!st.photos.length) { els.strip.style.display = 'none'; return; }
    els.strip.style.display = 'flex';
    els.strip.append(h('span', { class: 'qe-tip' }, 'الصور المقترحة — اضغطها للتكبير'));
    st.photos.forEach((p, i) => {
      const box = h('div', { class: 'qe-photo' + (p.used ? ' used' : ''), title: p.name, onclick: () => viewPhoto(i) },
        h('img', { src: p.dataUrl, alt: '' }),
        p.items ? h('span', { class: 'ph-n' }, String(p.items)) : null);
      box.append(h('span', { class: 'ph-x', title: 'حذف الصورة',
        onclick: e => { e.stopPropagation(); if (st.busy) return; st.photos.splice(i, 1); drawStrip(); drawBody(); saveDraft(); } }, '×'));
      els.strip.append(box);
    });
    els.strip.append(h('span', { class: 'qe-tip' }, '   أو الصق صورة بـ Ctrl+V'));
  }

  async function addFiles(files) {
    const room = 10 - st.photos.length;
    const arr = [...files].filter(f => f && /^image\//.test(f.type)).slice(0, Math.max(0, room));
    if (!arr.length) { if (room <= 0) toast('الحد عشر صور في الجلسة الواحدة', 'r'); return; }
    if (!IS() || !IS().prepImage) { toast('ماسح الصور غير محمّل', 'r'); return; }
    prog('ضغط الصور…');
    for (const f of arr) {
      try {
        const p = await IS().prepImage(f);
        if (p) st.photos.push({ id: uid(), name: clean(f.name, 60) || 'صورة', dataUrl: p.dataUrl, mime: p.mime, used: false, items: 0 });
      } catch (_) {}
    }
    prog(''); drawStrip(); drawBody(); saveDraft();
  }

  function onPaste(e) {
    if (!stage || !stage.isConnected || st.busy) return;
    const fl = e.clipboardData && e.clipboardData.files;
    if (fl && fl.length) { e.preventDefault(); addFiles(fl); }
  }

  function viewPhoto(i) {
    const p = st.photos[i]; if (!p) return;
    openModal({ title: p.name || 'الصورة', icon: 'eye', body: h('img', { class: 'qe-imgbig', src: p.dataUrl, alt: '' }), noPad: true, wide: true, xwide: true });
  }

  /* ───────────────────────── جسم النافذة ───────────────────────── */
  function drawBody() {
    if (!st || !els.body) return;
    if (st.rows.length) { drawGrid(); return; }
    els.body.innerHTML = '';
    els.body.append(h('div', { class: 'qe-drop', id: 'qe-drop' },
      h('h2', {}, 'صوّر كل العلبات في صورة واحدة'),
      h('p', {}, 'ضع الأدوية على سطح مستوٍ بحيث تظهر الواجهة الأمامية لكل علبة، ثم التقط صورة واحدة واضحة — عشرون أو ثلاثون صنفاً في لقطة واحدة. النظام يقرأها ويشرح لك ما فهمه عن كل صنف في جدول كبير، ولا يدخل شيء إلى المخزن حتى تضغط «حفظ الكل» وتؤكده.'),
      h('div', { class: 'qe-rules' },
        rule('١', 'واجهة واحدة تكفي', 'لا حاجة لكل وجه من العلبة — يكفي الشعار والجرعة والشكل وقراءة التعبئة المطبوعة.'),
        rule('٢', 'إضاءة ومسافة', 'وقفي على بُعد ٤٠–٦٠ سم بحيث تملأ العلبات الصورة، وبلا ظل فوق الأسماء.'),
        rule('٣', 'لا تكرار', 'لا تُدخل نفس الدواء بصورتين — النظام يدمج القراءات ويبحث عن الأصناف المسجّلة عندك تلقائياً.'),
        rule('٤', 'من الجوال', 'لو كان تطبيق التصوير على وضع «إدخال سريع» تصل الصورة هنا وحدها بلا أي إجراء منك.')),
      h('div', { style: { display: 'flex', gap: '10px', flexWrap: 'wrap', justifyContent: 'center' } },
        btn('اختر صوراً من الجهاز', 'camera', 'g', () => els.file.click()),
        btn('لصق صورة (Ctrl+V)', 'upload', 'b', () => toast('اضغط Ctrl+V بعد نسخ الصورة')),
        btn('استقبال من الجوال', 'download', 'n', () => toast(st.inbox ? 'قناة الجوال تعمل — ارفع الصورة وستصل هنا' : 'قناة الجوال تحتاج اتصال المزامنة (Firebase)', st.inbox ? 'g' : 'r')))));
    const dz = els.body.querySelector('.qe-drop');
    ['dragenter', 'dragover'].forEach(k => dz.addEventListener(k, e => { e.preventDefault(); dz.classList.add('hot'); }));
    ['dragleave', 'drop'].forEach(k => dz.addEventListener(k, e => { e.preventDefault(); dz.classList.remove('hot'); }));
    dz.addEventListener('drop', e => { if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files); });
    prog('');
  }
  const rule = (n, t, d) => h('div', { class: 'qe-rule' }, h('b', {}, n + ' ' + t), h('div', {}, d));

  /* ───────────────────────── الجدول الكبير ───────────────────────── */
  function visible() {
    const q = st.q.toLowerCase();
    return st.rows.map((r, i) => ({ r, i })).filter(x => {
      if (st.filter === 'todo' && x.r.saved) return false;
      if (st.filter === 'done' && !x.r.saved) return false;
      if (st.filter === 'ask' && (x.r.saved || askCount(x.r) === 0)) return false;
      if (q && !((x.r.brandName || '') + ' ' + (x.r.sci || '') + ' ' + (x.r.company || '') + ' ' + (x.r.barcode || '')).toLowerCase().includes(q)) return false;
      return true;
    });
  }
  function askCount(r) {
    const f = r.flags || {};
    return Object.keys(FLAG_LABEL).filter(k => f[k] === 'ask').length;
  }

  function drawGrid() {
    const keep = () => { const b = els.body.querySelector('.tbl-scroll'); return b ? { t: b.scrollTop, l: b.scrollLeft } : null; };
    const old = keep();
    els.body.innerHTML = '';

    const bar = h('div', { class: 'qe-bar' },
      h('input', { placeholder: 'تصفية بالاسم أو الشركة أو الباركود…', value: st.q, style: { width: '280px' },
        oninput: e => { st.q = e.target.value; refreshList(); } }),
      sel(['all', 'todo', 'ask', 'done'], ['كل الأصناف', 'غير المحفوظة', 'تحتاج مراجعة', 'المحفوظة'], st.filter, v => { st.filter = v; refreshList(); }),
      h('span', { class: 'qe-tip', style: { fontWeight: '900', color: 'var(--muted)' } }, '٪ ربح التلقائي'),
      h('input', { type: 'number', min: '0', step: 'any', value: st.pct, style: { width: '82px' },
        oninput: e => { st.pct = num(e.target.value); st.rows.forEach(r => { if (!r.saved) { autoSale(r); paintStat(r); } }); } }),
      h('div', { class: 'qe-sp' }),
      h('button', { class: 'qe-mini', title: 'انسخ التعبئة/الجرد/السعر/الباركود/الإكسباير من المظلّل إلى كل الأسطر غير المحفوظة',
        onclick: () => fillAll() }, 'تكرار العمود المظلل للجميع'),
      btn('＋ صورة وتحليل', 'camera', 'b', () => run()));

    const wrap = h('div', { class: 'qe-grid' });
    const sc = h('div', { class: 'tbl-scroll' });
    const tbl = h('table', { class: 'tbl qe-tbl' });
    const thead = h('thead');
    thead.append(h('tr', {}, COLS.map(c => h('th', { style: { minWidth: c.w } },
      c.t, c.fill ? h('button', { class: 'qe-mini', style: { marginInlineStart: '6px' }, title: 'تكرار هذا العمود من السطر المظلل',
        onclick: () => fillCol(c.k) }, '⇩') : null))));
    const tb = h('tbody');
    tbl.append(thead, tb);
    sc.append(tbl);
    wrap.append(sc);
    els.body.append(bar, wrap);
    els.tb = tb;
    refreshList();
    if (old) { sc.scrollTop = old.t; sc.scrollLeft = old.l; }
    prog('');
  }

  function sel(vals, labels, cur, fn) {
    const s = h('select', {}, vals.map((v, i) => h('option', { value: v, selected: v === cur }, labels[i])));
    s.addEventListener('change', () => fn(s.value));
    return s;
  }

  function refreshList() {
    if (!els.tb) return;
    const af = document.activeElement;
    const spot = af && af.dataset && af.dataset.k && els.tb.contains(af) ? { k: af.dataset.k, ix: af.closest('tr') ? af.closest('tr').dataset.ix : null, s: af.selectionStart, e: af.selectionEnd } : null;
    els.tb.innerHTML = '';
    const vs = visible();
    vs.forEach(({ r, i }, n) => els.tb.append(rowNode(r, i, n)));
    if (!vs.length) els.tb.append(h('tr', {}, h('td', { colspan: String(COLS.length), style: { textAlign: 'center', padding: '26px', color: 'var(--muted)', fontWeight: '900' } }, 'لا يوجد صنف يطابق التصفية')));
    if (spot && spot.ix != null) {
      const tr = els.tb.querySelector('tr[data-ix="' + spot.ix + '"]');
      const el = tr && tr.querySelector('[data-k="' + spot.k + '"]');
      if (el) { el.focus({ preventScroll: true }); if (el.setSelectionRange && spot.s != null) { try { el.setSelectionRange(spot.s, spot.e); } catch (_) {} } }
    }
    chips();
  }

  /* السطر: خلية لكل حقل، والمظلّل بالأسهم يعمل من نفس الصفحة (ix = رقمه الحقيقي، n = ظاهر للتصفية) */
  function rowNode(r, ix, n) {
    const tr = h('tr', { class: (r.saved ? 'qe-done ' : '') + (!r.saved && askCount(r) ? 'qe-todo ' : '') + (r.open ? 'qe-open' : ''), 'data-ix': String(ix) });
    tr.append(h('td', {}, h('div', { class: 'qe-seq' }, String(n + 1))));

    /* الصورة المصغّرة */
    const ph = st.photos[r.photoIx];
    tr.append(h('td', {}, ph ? h('div', { class: 'qe-thumb', title: 'تكبير الصورة', onclick: () => viewPhoto(r.photoIx) }, h('img', { src: ph.dataUrl, alt: '' }))
      : h('span', { class: 'qe-hint' }, r.photoLost ? 'صورة منتهية' : '—')));

    /* خلية الفهم: كل ما قرأه النظام عن الصنف في مكان واحد */
    const und = h('td', {});
    r._n = { tr, und, link: null, fact: null, hint: null, stat: null, badges: null };
    tr.append(und);
    paintUnd(r);

    /* التعبئة */
    tr.append(packCell(r));
    /* = عدد الوحدات الصغيرة */
    const fc = h('td', {});
    r._n.fact = h('div', { class: 'qe-fact' });
    fc.append(r._n.fact);
    tr.append(fc);

    tr.append(numCell(r, 'stock', 'الجرد'));
    tr.append(numCell(r, 'buyTop', 'سعر الكبرى'));
    tr.append(numCell(r, 'saleBase', 'سعر الصغرى'));

    /* الباركود */
    const bt = h('td', {});
    const bi = h('input', { class: 'qe-in', 'data-k': 'barcode', value: r.barcode || '', placeholder: 'EAN أو اتركه فارغاً', dir: 'ltr', inputmode: 'numeric', disabled: r.saved ? 'true' : null });
    bi.addEventListener('input', () => { r.barcode = clean(bi.value, 24).replace(/[^0-9A-Za-z-]/g, ''); bi.value = r.barcode; linkRow(r); paintStat(r); saveDraftSoon(); });
    bt.append(bi);
    r._n.bhint = h('div', { class: 'qe-hint' });
    bt.append(r._n.bhint);
    bt.append(h('div', { class: 'qe-btns' }, h('button', { class: 'qe-mini', disabled: r.saved ? 'true' : null,
      onclick: () => { if (r.saved) return; r.barcode = genBarcode(); bi.value = r.barcode; linkRow(r); paintStat(r); saveDraftSoon(); } }, 'توليد')));
    tr.append(bt);

    /* الإكسباير */
    const et = h('td', {});
    const ei = h('input', { class: 'qe-in', type: 'month', 'data-k': 'expiry', value: r.expiry || '', disabled: r.saved ? 'true' : null });
    ei.addEventListener('change', () => { r.expiry = clean(ei.value, 10); paintStat(r); saveDraftSoon(); });
    et.append(ei);
    et.append(h('div', { class: 'qe-btns' }, h('button', { class: 'qe-mini', disabled: r.saved ? 'true' : null, onclick: () => { if (r.saved) return; r.expiry = guessExpiry(r); ei.value = r.expiry; paintStat(r); saveDraftSoon(); } }, 'تخمين +24ش')));
    tr.append(et);

    /* الحالة */
    const sp = h('td', {});
    r._n.stat = h('div', { class: 'qe-stat' });
    sp.append(r._n.stat);
    paintStat(r);
    tr.append(sp);

    if (r.open) tr.after(detailRow(r));
    tr.addEventListener('focusin', () => { st.mark = ix; });
    paintFact(r);
    return tr;
  }

  function numCell(r, key, ph) {
    const td = h('td', {});
    const i = h('input', { class: 'qe-in', type: 'number', min: '0', step: 'any', 'data-k': key, value: r[key] === '' || r[key] == null ? '' : r[key], placeholder: ph, disabled: r.saved ? 'true' : null });
    i.addEventListener('input', () => {
      r[key] = i.value === '' ? '' : r2(i.value);
      if (key === 'saleBase') r.autoSale = false; else autoSale(r);
      paintFact(r); paintStat(r); saveDraftSoon();
    });
    td.append(i);
    if (key === 'saleBase') { r._n.hint = h('div', { class: 'qe-hint' }); td.append(r._n.hint); }
    if (key === 'stock') td.append(h('div', { class: 'qe-hint' }, r.productId ? 'يُضاف للمخزون الحالي' : 'جرد افتتاحي'));
    if (key === 'buyTop') td.append(h('div', { class: 'qe-hint' }, 'سعر التعبئة الكبيرة كاملة'));
    return td;
  }

  function packCell(r) {
    const td = h('td', {});
    const box = h('div', { class: 'qe-pack' });
    const names = unitOpts();
    const mk = (key, val, w) => {
      const s = h('select', { class: 'qe-in pu', 'data-k': key, style: w ? { width: w } : null, disabled: r.saved ? 'true' : null },
        names.map(n => h('option', { value: n, selected: n === val }, n)));
      s.addEventListener('change', () => { r[key] = s.value; paintFact(r); saveDraftSoon(); });
      return s;
    };
    const qty = (key, val) => {
      const i = h('input', { class: 'qe-in pn', type: 'number', min: '1', step: '1', 'data-k': key, value: val || '', placeholder: 'عدد', disabled: r.saved ? 'true' : null });
      i.addEventListener('input', () => { r[key] = i.value === '' ? '' : int(i.value, 9999); paintFact(r); autoSale(r); paintStat(r); saveDraftSoon(); });
      return i;
    };
    box.append(
      h('div', { class: 'qe-prow' }, mk('uBig', r.uBig), h('span', { class: 'par' }, 'فيه'), qty('nMid', r.nMid)),
      h('div', { class: 'qe-prow' },
        h('select', { class: 'qe-in pu', 'data-k': 'uMid', disabled: r.saved ? 'true' : null },
          h('option', { value: '', selected: !r.uMid }, '— بلا مستوى وسط —'),
          names.filter(n => n !== r.uBig && n !== r.uSmall).map(n => h('option', { value: n, selected: n === r.uMid }, n))),
        qty('nSmall', r.nSmall)),
      h('div', { class: 'qe-prow' }, h('span', { class: 'par' }, 'الصغرى'), mk('uSmall', r.uSmall)));
    td.append(box);
    if (r.packText) td.append(h('div', { class: 'qe-hint', title: r.packText }, 'مطبوع: ' + r.packText.slice(0, 60)));
    return td;
  }
  function unitOpts() {
    const base = (state.settings.unitNames || []).slice();
    const extra = ['قطعة', 'شريط', 'علبة', 'كرتون', 'باكيت', 'قنينة'];
    st.rows.forEach(r => { extra.push(r.uBig, r.uMid, r.uSmall); });
    return [...new Set(base.concat(extra).filter(Boolean))];
  }

  /* الخلايا المشتقّة فقط — من دون إعادة رسم حتى لا يفقد المستخدم تركيزه */
  function paintFact(r) {
    if (!r._n || !r._n.fact) return;
    const u = units(r);
    r._n.fact.innerHTML = '';
    r._n.fact.append(h('div', {}, '= ' + fmt(baseF(u)) + ' ' + (u[u.length - 1].name || '')),
      h('small', {}, costPer(r) ? 'تكلفة الصغرى ' + fmt(costPer(r)) : 'حدّد سعر الكبرى'));
  }
  function paintUnd(r) {
    if (!r._n || !r._n.und) return;
    const box = r._n.und;
    box.innerHTML = '';
    const dose = (r.doseV || '') + (r.doseU || '');
    box.append(
      h('div', { class: 'u1', dir: 'ltr' }, r.brandName || '—', dose ? h('em', {}, ' ' + dose) : null, r.form ? h('span', { class: 'u3' }, ' · ' + r.form) : null),
      r.sci ? h('div', { class: 'u2', dir: 'ltr' }, 'علمي: ' + r.sci) : h('div', { class: 'u3' }, 'بلا اسم علمي'),
      h('div', { class: 'u2' }, 'الشركة: ' + (r.company || '؟')),
      h('div', { class: 'u3' }, 'تعبئة مقروءة: ' + (r.packText || 'لا شيء على العلبة') + (r.packEvidence ? ' · ' + r.packEvidence : '')));
    const bg = h('div', { class: 'qe-badges' });
    const f = r.flags || {};
    Object.keys(FLAG_LABEL).forEach(k => {
      const s = f[k] === 'ok' ? 'ok' : f[k] === 'fixed' ? 'fix' : f[k] === 'ask' ? 'ask' : null;
      if (!s) return;
      bg.append(h('span', { class: 'qb ' + s, title: s === 'ok' ? 'القراءتان اتفقتا' : s === 'fix' ? 'حسمها القاضي' : 'غير واضح — يؤكد الصيدلاني' }, FLAG_LABEL[k] + (s === 'ask' ? ' ?' : s === 'fix' ? ' !' : ' ✓')));
    });
    if (r.confidence) bg.append(h('span', { class: 'qb ' + (r.confidence >= 75 ? 'ok' : r.confidence >= 50 ? 'fix' : 'ask') }, 'دقة ' + r.confidence + '%'));
    box.append(bg);
    const lk = h('div', { class: 'qe-link ' + (r.productId ? 'ex' : 'new') });
    if (r.productId) {
      const p = findProd(r.productId);
      const pu = (p && p.units) || [];
      lk.append(p ? h('span', {}, 'موجود بالمخزن: ' + p.brandName + ' · مخزون ' + fmt(p.stockBase || 0) + ' ' + ((pu[pu.length - 1] || {}).name || '')) : h('span', {}, 'مرتبط بصنف محذوف'));
      if (p && baseF(units(r)) !== baseF(p.units || [])) lk.append(h('div', { class: 'qe-hint', style: { color: '#92400e' } },
        'تعبئتك لا تطابق المسجلة (' + fmt(baseF(p.units || [])) + ' وحدة صغرى) — الزيادة تُحسب بالتعبئة المسجلة، وتعديلها من صفحة الصنف'));
    } else lk.append(h('span', {}, r.forceNew ? 'صنف جديد بأمرك' : 'صنف جديد — لا يوجد مطابق'));
    box.append(lk);
    box.append(h('div', { class: 'qe-btns' },
      h('button', { class: 'qe-mini', onclick: () => { r.open = !r.open; if (r.open) r._n.tr.after(detailRow(r)); else closeDetail(r); } }, r.open ? 'إخفاء التفاصيل' : 'تفاصيل ومقارنة'),
      (r.alts && r.alts.length > 1) || r.productId ? h('button', { class: 'qe-mini', onclick: () => linkPicker(r) }, 'تبديل الربط') : null,
      h('button', { class: 'qe-mini', onclick: () => { r.forceNew = !r.forceNew; linkRow(r); paintUnd(r); paintStat(r); saveDraftSoon(); } }, r.forceNew ? 'دعه مرتبطاً' : 'صنّفه جديدًا')));
  }
  function paintStat(r) {
    if (!r._n || !r._n.stat) return;
    const box = r._n.stat;
    box.innerHTML = '';
    if (r.saved) {
      box.append(h('span', { class: 'qb ok' }, '✓ محفوظ'),
        h('div', { class: 'qe-btns' },
          h('button', { class: 'qe-mini', onclick: () => printOne(r) }, 'ملصق'),
          h('button', { class: 'qe-mini', onclick: () => undoSave(r) }, 'فكّ الحفظ')));
      return;
    }
    const a = askCount(r);
    box.append(h('span', { class: 'qb ' + (a ? 'ask' : 'ok') }, a ? a + ' خانة تحتاج تأكيداً' : 'جاهز للحفظ'),
      r.dupBar ? h('div', { class: 'qb ask', title: 'الباركود مستخدم عند ' + r.dupName }, 'باركود مكرر!') : null,
      r.expired ? h('div', { class: 'qb ask' }, 'إكسباير منتهٍ!') : null,
      h('div', { class: 'qe-btns' },
        h('button', { class: 'qe-mini', onclick: () => saveOne(r) }, 'حفظ هذا'),
        h('button', { class: 'qe-mini r', onclick: () => dropRow(r) }, 'حذف')));
    if (r._n.hint) {
      const cp = costPer(r), sp = num(r.saleBase);
      r._n.hint.className = 'qe-hint ' + (cp && sp ? (sp >= cp ? 'pos' : 'neg') : '');
      r._n.hint.textContent = cp && sp ? 'ربح ' + Math.round((sp / cp - 1) * 1000) / 10 + '% · تكلفة الصغرى ' + fmt(cp) : (r.autoSale ? 'مشتق تلقائياً — عدّله إن أردت' : 'حدّد السعرين');
    }
    if (r._n.bhint) r._n.bhint.textContent = r.barcode ? (r.dupBar ? 'مستخدم لدى صنف آخر' : 'سيُطبع على الملصق') : 'يُولَّد عند الحفظ';
  }
  function closeDetail(r) {
    const nx = r._n && r._n.tr.nextElementSibling;
    if (nx && nx.classList.contains('qe-detail')) nx.remove();
  }
  function detailRow(r) {
    const rows = [
      ['النص المطبوع المقروء', r.read || '—'],
      ['القراءة الأولى', r.aText || '—'],
      ['القراءة الثانية', r.bText || '—'],
      ['مرجع التعبئة', r.packEvidence || '—'],
      ['الاسم الذي سيُحفظ', r.productId ? 'لن يتغير (صنف مسجّل)' : nameLine(r)],
    ];
    const noteInp = h('input', { class: 'qe-in', style: { maxWidth: '520px', display: 'inline-block' }, value: r.note || '', placeholder: 'اكتب ملاحظة خاصة بهذا الصنف (لا تظهر في المخزون)' });
    noteInp.addEventListener('input', () => { r.note = clean(noteInp.value, 200); saveDraftSoon(); });
    const box = h('div', { class: 'qe-dbox' });
    rows.forEach(x => box.append(h('div', {}, h('span', { class: 'dk' }, x[0] + ': '), h('span', { class: 'dv' }, x[1]))));
    box.append(h('div', {}, h('span', { class: 'dk' }, 'ملاحظةك: '), noteInp));
    const tr = h('tr', { class: 'qe-detail' }, h('td', { colspan: String(COLS.length) }, box));
    return tr;
  }

  /* ───────────────────────── منطق التعبئة والأسعار ───────────────────────── */
  /* التعبئة ← نفس نموذج النظام: units الكبرى أولاً والصغرى أخيراً، وperNext = عدد الأصغر داخل الأكبر */
  function units(r) {
    const small = { name: r.uSmall || 'قطعة', perNext: 1 };
    const nMid = Math.max(1, int(r.nMid, 99999));
    if (r.uMid) return [{ name: r.uBig || 'كرتون', perNext: nMid }, { name: r.uMid, perNext: Math.max(1, int(r.nSmall, 9999)) }, small];
    if (nMid > 1) return [{ name: r.uBig || 'علبة', perNext: nMid }, small];
    return [small];
  }
  function baseF(u) { if (!u || !u.length) return 1; let f = 1; u.forEach(x => { f *= Math.max(1, int(x.perNext, 99999)); }); return f; }
  function costPer(r) { const bf = baseF(units(r)), b = num(r.buyTop); return b > 0 ? r2(b / bf) : 0; }
  function autoSale(r) {
    const cp = costPer(r);
    if (r.saleBase === '' || r.saleBase == null || r.autoSale) {
      if (cp > 0) { const v = Math.round(cp * (1 + (num(st.pct) || 0) / 100)); r.saleBase = v; r.autoSale = true; }
      else { r.saleBase = ''; r.autoSale = false; }
    }
    const el = r._n && r._n.tr ? r._n.tr.querySelector('[data-k="saleBase"]') : null;
    if (el && document.activeElement !== el) el.value = r.saleBase === '' ? '' : r.saleBase;
  }
  function nameLine(r) {
    const brand = liftCompany(clean(r.brandName, 90), r.company);
    const dose = (r.doseV || '') + (r.doseU || '');
    return [brand, dose, r.form].filter(Boolean).join(' ').trim();
  }
  function liftCompany(name, company) {
    const cs = new Set(clean(company, 60).toLowerCase().split(/[^a-z0-9\u0600-\u06FF]+/).filter(w => w.length >= 4));
    if (!cs.size) return name;
    const keep = name.split(/\s+/).filter(w => w && !cs.has(w.toLowerCase()));
    return keep.length ? keep.join(' ') : name;
  }
  function guessExpiry(r) {
    const e = r.expiry;
    if (e && /^\d{4}-\d{2}$/.test(e) && e >= nowYM()) return e;
    const d = new Date(); d.setMonth(d.getMonth() + 24);
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
  }

  /* الربط بالمخزن — يعيد استخدام محرك مطابقة الماسح (اسم ← مرشحين ← جرعة/شركة/شكل يحسم) */
  function linkRow(r) {
    let pid = null, alts = [], marks = null, amb = false;
    const X = IS();
    if (r.barcode) { const by = state.products.find(p => !p.deleted && (p.barcodes || []).includes(r.barcode)); if (by) pid = by.id; }
    if (!pid && X && X.autoLink) {
      const shim = { name: r.brandName, company: r.company, dose: (r.doseV || '') + (r.doseU || ''), form: r.form, forceNew: !!r.forceNew };
      X.autoLink(shim);
      pid = shim.productId || null; alts = shim.alts || []; marks = shim.marks || null; amb = !!shim.ambiguous;
    }
    r.alts = alts; r.marks = marks; r.ambiguous = amb;
    r.productId = r.forceNew ? null : pid;
    r.dupBar = ''; r.dupName = '';
    if (r.barcode) {
      const other = state.products.find(p => !p.deleted && p.id !== r.productId && (p.barcodes || []).includes(r.barcode));
      if (other) { r.dupBar = r.barcode; r.dupName = other.brandName; }
    }
    r.expired = !!r.expiry && r.expiry < nowYM();
    return r;
  }

  function linkPicker(r) {
    const body = h('div', {});
    const inp = h('input', { class: 'qe-in', placeholder: 'ابحث في مخزنك…', style: { marginBottom: '10px' } });
    const list = h('div', { class: 'qe-list' });
    const draw = q => {
      list.innerHTML = '';
      const res = (q ? searchProducts(q) : []).slice(0, 20);
      if (!res.length && !q) (r.alts || []).forEach(id => { const p = findProd(id); if (p) res.push(p); });
      if (!res.length) list.append(h('div', { class: 'sug-empty' }, 'لا نتائج'));
      res.forEach(p => list.append(h('div', { class: 'qe-li', onclick: () => { r.productId = p.id; r.forceNew = false; m.close(); linkRow(r); paintUnd(r); paintStat(r); saveDraftSoon(); } },
        p.brandName, h('small', {}, (p.company || '') + ' · مخزون ' + fmt(p.stockBase || 0)))));
    };
    inp.addEventListener('input', () => draw(inp.value.trim()));
    body.append(inp, list);
    draw('');
    const m = openModal({ title: 'اربط الصنف بسجل موجود', icon: 'search', body, wide: true, actions: [{ label: 'اتركه صنفاً جديداً', cls: 'r', onClick: c => { c(); r.forceNew = true; r.productId = null; linkRow(r); paintUnd(r); paintStat(r); saveDraftSoon(); } }] });
  }

  /* ───────────────────────── التكرار العمودي (توفير الوقت على 20 سطراً) ───────────────────────── */
  function markRow() { return st.rows[st.mark] || st.rows[0]; }
  function targets() { return st.rows.filter(r => !r.saved); }
  function fillCol(key) {
    const map = { pack: ['uBig', 'nMid', 'uMid', 'nSmall', 'uSmall'], stock: ['stock'], buyTop: ['buyTop'], saleBase: ['saleBase'], expiry: ['expiry'] }[key];
    const list = targets();
    if (!list.length) return toast('لا توجد أسطر غير محفوظة', 'r');
    if (key === 'barcode') {
      let n = 0;
      list.forEach(r => { if (!r.barcode) { r.barcode = genBarcode(); n++; } linkRow(r); paintStat(r); });
      saveDraftSoon();
      toast(n ? 'وُلِّد باركود لـ ' + n + ' صنفاً (الفارغة فقط)' : 'كل الأسطر لها باركود');
      return;
    }
    if (!map) return;
    const src = markRow();
    if (!src) return toast('ظلّل سطراً أولاً بالضغط على إحدى خلاياه', 'r');
    map.forEach(k => list.forEach(r => { r[k] = src[k]; }));
    list.forEach(r => { autoSale(r); linkRow(r); });
    refreshList(); saveDraftSoon();
    toast('طُبِّق عمود «' + ((COLS.find(c => c.k === key) || {}).t || '') + '» على ' + list.length + ' سطراً');
  }
  function fillAll() {
    const src = markRow();
    if (!src) return toast('ظلّل سطراً أولاً', 'r');
    ['uBig', 'nMid', 'uMid', 'nSmall', 'uSmall', 'stock', 'expiry'].forEach(k => targets().forEach(r => { r[k] = src[k]; }));
    targets().forEach(r => autoSale(r));
    refreshList(); saveDraftSoon();
    toast('نُسخت التعبئة والجرد والإكسباير من السطر المظلل');
  }

  /* ───────────────────────── الحفظ ───────────────────────── */
  function validate(r) {
    const e = [];
    if (!clean(r.brandName, 90)) e.push('الاسم التجاري غير مقروء — اكتبه');
    if (!r.productId) {
      if (!(num(r.buyTop) > 0)) e.push('سعر شراء الوحدة الكبيرة مطلوب');
      if (!(num(r.saleBase) > 0)) e.push('سعر بيع الوحدة الصغيرة مطلوب');
    }
    if (r.barcode && r.dupBar) e.push('الباركود مستخدم لدى «' + r.dupName + '»');
    if (r.expiry && !/^\d{4}-\d{2}$/.test(r.expiry)) e.push('الإكسباير غير مكتمل (شهر/سنة)');
    if (r.expiry && r.expiry < nowYM()) e.push('الإكسباير منتهٍ — لن يُحفظ قبل تغييره');
    if (r.stock !== '' && num(r.stock) < 0) e.push('الجرد لا يكون سالباً');
    if (r.uMid && !(int(r.nSmall, 9999) > 0)) e.push('عدد الصغرى داخل الوسطى ناقص');
    return e;
  }

  async function rememberCompany(name) {
    const nm = clean(name, 70); if (!nm) return;
    const cs = state.settings.companies = state.settings.companies || [];
    if (cs.some(c => c && c.name && c.name.trim().toLowerCase() === nm.toLowerCase())) return;
    cs.push({ name: nm, country: '' });
    await save('settings', state.settings);
  }
  async function rememberUnits(r) {
    const list = state.settings.unitNames = state.settings.unitNames || [];
    let ch = false;
    units(r).forEach(u => { if (u.name && !list.includes(u.name)) { list.push(u.name); ch = true; } });
    if (ch) await save('settings', state.settings);
  }
  function countryOf(name) {
    const c = (state.settings.companies || []).find(x => x && x.name && x.name.trim().toLowerCase() === String(name || '').trim().toLowerCase());
    return c && c.country ? c.country : '';
  }

  async function writeProduct(r) {
    const u = units(r), bf = baseF(u);
    const emp = me();
    if (r.productId) {
      const old = findProd(r.productId);
      if (!old) throw new Error('الصنف المرتبط حُذف — أرشّف السطر أو اربطه بغيره');
      const p = JSON.parse(JSON.stringify(old));
      p.barcodes = p.barcodes || [];
      if (r.barcode && !p.barcodes.includes(r.barcode)) p.barcodes.push(r.barcode);
      if (r.expiry) p.expiry = r.expiry;
      if (num(r.buyTop) > 0) p.purchasePriceTop = num(r.buyTop);
      if (num(r.saleBase) > 0) p.salePriceBase = num(r.saleBase);
      const add = r.stock === '' ? 0 : num(r.stock);
      p.stockLog = Array.isArray(p.stockLog) ? p.stockLog : [];
      if (add !== 0) {
        p.stockBase = r2((p.stockBase || 0) + add);
        p.stockLog.push({ ts: Date.now(), kind: 'adjust', delta: add, note: 'الإدخال السريع — إضافة جرد', empId: emp ? emp.id : '', empName: emp ? emp.name : '' });
      }
      await save('products', p);
      await rememberCompany(p.company);
      return p;
    }
    if (r.uMid && int(r.nSmall, 9999) <= 0) r.nSmall = 1;
    const profit = +(state.settings.profitPct ?? 30);
    const sale = num(r.saleBase) > 0 ? num(r.saleBase) : Math.round(num(r.buyTop) / bf * (1 + profit / 100));
    const code = r.barcode || genBarcode();
    const opening = r.stock === '' ? 0 : num(r.stock);
    const p = {
      id: uid(), brandName: nameLine(r), scientificName: clean(r.sci, 90), barcodes: [code],
      form: r.form || 'Tab', dose: (r.doseV || '') + (r.doseU || ''), expiry: r.expiry || '', featured: false,
      company: clean(r.company, 70), country: countryOf(clean(r.company, 70)),
      units: u, purchasePriceTop: num(r.buyTop), salePriceBase: sale, stockBase: opening,
      stockLog: opening ? [{ ts: Date.now(), kind: 'opening', delta: opening, note: 'جرد افتتاحي — الإدخال السريع', empId: emp ? emp.id : '', empName: emp ? emp.name : '' }] : [],
      createdAt: Date.now(), fromQuickEntry: true,
    };
    await rememberCompany(p.company); await rememberUnits(r);
    await save('products', p);
    return p;
  }

  async function saveOne(r) {
    if (r.saved) return true;
    const e = validate(r);
    if (e.length) { showErrors([{ r, e }]); return false; }
    try {
      const p = await writeProduct(r);
      r.saved = true; r.savedId = p.id; r.savedName = p.brandName; r.newProduct = !r.productId || !findProd(r.productId);
      st.lastNew.push(p);
      syncProductEverywhere(p);
      linkRow(r);
      refreshList(); chips(); saveDraftSoon();
      return true;
    } catch (err) {
      toast('فشل حفظ «' + (r.brandName || 'بدون اسم') + '»: ' + ((err && err.message) || err), 'r');
      return false;
    }
  }

  async function saveAll() {
    if (st.busy) return toast('انتظر حتى تنتهي القراءة', 'r');
    const list = targets();
    if (!list.length) return toast('كل الأصناف محفوظة', 'b');
    const bad = list.map(r => ({ r, e: validate(r) })).filter(x => x.e.length);
    if (bad.length) return showErrors(bad);
    const fresh = list.filter(r => !r.productId).length;
    const yes = await confirmBox(`سيُضاف ${list.length} صنفاً إلى المخزن الآن (${fresh} صنفاً جديداً، و${list.length - fresh} زيادة على أصناف مسجّلة). لن يُحفظ شيء قبل تأكيدك.`,
      { okLabel: 'نعم، احفظ الكل', icon: 'check' });
    if (!yes) return;
    prog('جارٍ الحفظ…');
    st.busy = true;
    let ok = 0; const fail = [];
    try {
      for (const r of list) { if (!st) break; const v = await saveOne(r); if (v) ok++; else fail.push(r.brandName || '—'); }
    } finally { if (st) st.busy = false; }
    if (!st) return;
    prog('');
    if (fail.length) toast(`حُفظ ${ok} — تعذّر ${fail.length} (${fail.slice(0, 3).join('، ')})`, 'r');
    else toast(`تم حفظ ${ok} صنفاً في المخزن`);
    if (ok) askLabels();
  }

  function showErrors(bad) {
    const body = h('div', { class: 'qe-errlist' }, bad.slice(0, 30).map(x => h('div', { class: 'qe-errrow' },
      h('b', {}, x.r.brandName || 'سطر بلا اسم'),
      h('div', {}, x.e.join(' · ')),
      h('div', {}, h('button', { class: 'qe-mini', onclick: () => { m.close(); jumpTo(x.r); } }, 'اذهب للسطر')))));
    const m = openModal({ title: bad.length + ' سطراً يحتاج إكمالاً قبل الحفظ', icon: 'warn', body, wide: true, actions: [{ label: 'تم', cls: 'g', onClick: c => c() }] });
  }
  function jumpTo(r) {
    st.filter = 'all'; st.q = ''; refreshList();
    const ix = st.rows.indexOf(r);
    const tr = els.tb ? els.tb.querySelector('tr[data-ix="' + ix + '"]') : null;
    if (!tr) return;
    tr.scrollIntoView({ block: 'center' });
    const el = tr.querySelector('.qe-in');
    if (el) el.focus();
  }

  function dropRow(r) {
    const ix = st.rows.indexOf(r);
    if (ix < 0) return;
    if (!r.saved && askCount(r) === 0 && clean(r.brandName, 1)) {
      confirmBox('حذف هذا السطر؟ لن يُحفظ في المخزن.', { danger: true, okLabel: 'احذفه' }).then(y => { if (y) cut(ix); });
      return;
    }
    cut(ix);
  }
  function cut(ix) {
    const r = st.rows[ix];
    closeDetail(r);
    st.rows.splice(ix, 1);
    if (st.mark >= st.rows.length) st.mark = Math.max(0, st.rows.length - 1);
    if (!st.rows.length) drawBody(); else refreshList();
    saveDraftSoon();
  }

  async function clearAll() {
    if (st.busy) return;
    const un = targets().length;
    if (un || st.photos.length) {
      const yes = await confirmBox(un ? `سيُحذف ${un} صنفاً غير محفوظ نهائياً${st.photos.length ? ' وتُمسح الصور' : ''} — والمتابعة؟` : 'تُمسح الصور والأصناف المحفوظة من هذه النافذة؟', { danger: true, okLabel: 'امسح الكل' });
      if (!yes) return;
    }
    st.rows.filter(r => r.open).forEach(closeDetail);
    st.rows = []; st.photos = []; st.mark = 0;
    DB.del('meta', 'qeDraft').catch(() => {});
    drawStrip(); drawBody(); chips();
  }

  function undoSave(r) {
    if (!r.saved || !r.savedId) return;
    confirmBox('فكّ الحفظ يُخرج الصنف من الجدول فقط — ما تم تسجيله في المخزن يبقى كما هو (تعديله من صفحة الصنف).', { okLabel: 'أخرج السطر' }).then(y => {
      if (!y) return;
      const sid = r.savedId;
      r.saved = false; r.savedId = '';
      const i = st.lastNew.findIndex(p => p && p.id === sid);
      if (i >= 0) st.lastNew.splice(i, 1);
      refreshList();
    });
  }

  /* ملصقات الباركود للأصناف الجديدة في هذه الجلسة */
  function askLabels() {
    const news = st.lastNew.filter(p => p && p.barcodes && p.barcodes.length);
    if (!news.length) return;
    confirmBox(`طباعة ملصقات باركود لـ ${news.length} صنفاً جديداً الآن؟`, { okLabel: 'نعم، اطبع', icon: 'print' }).then(y => { if (y) askPrint(); });
  }
  function askPrint() {
    const news = st.lastNew.filter(p => p && p.barcodes && p.barcodes.length);
    if (!news.length) return toast('لا توجد أصناف جديدة محفوظة في هذه الجلسة', 'b');
    const qty = h('input', { class: 'qe-in', type: 'number', min: '1', value: '20', style: { width: '120px' } });
    const body = h('div', { style: { display: 'flex', flexDirection: 'column', gap: '10px' } },
      h('div', { style: { fontWeight: '800' } }, 'عدد الملصقات لكل صنف:'), qty,
      h('div', { class: 'qe-list' }, news.map(p => h('label', { class: 'qe-li' },
        h('input', { type: 'checkbox', checked: 'true', dataset: { pid: p.id } }), ' ' + p.brandName))));
    openModal({ title: 'ملصقات الباركود', icon: 'print', body, wide: true, actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'اطبع', cls: 'g', icon: 'print', onClick: async c => {
          const n = Math.max(1, Math.min(500, int(qty.value, 500)));
          const picked = [...body.querySelectorAll('input[type=checkbox]')].filter(x => x.checked).map(x => news.find(p => p.id === x.dataset.pid)).filter(Boolean);
          c();
          if (!picked.length) return toast('لم تختر أي صنف', 'r');
          for (const p of picked) { await printBarcodeLabels(p.brandName, p.barcodes[0], n); await sleep(400); }
        } }] });
  }
  function printOne(r) {
    const p = findProd(r.savedId || r.productId);
    if (!p) return toast('الصنف غير موجود', 'r');
    printBarcodeLabels(p.brandName, (p.barcodes || [''])[0], 20);
  }

  /* ───────────────────────── المسودة المحلية (IndexedDB فقط — لا تخرج للسحابة) ───────────────────────── */
  let draftT = null;
  function saveDraftSoon() { clearTimeout(draftT); draftT = setTimeout(saveDraft, 700); chips(); }
  function saveDraft() {
    if (!st) return;
    const rows = st.rows.map(r => {
      const o = {}; Object.keys(r).forEach(k => { if (k !== '_n' && k !== 'alts' && k !== 'marks' && typeof r[k] !== 'function') o[k] = r[k]; });
      o.alts = (r.alts || []).slice(0, 8);
      return o;
    });
    DB.put('meta', { id: 'qeDraft', ts: Date.now(), rows, photos: st.photos.map(p => ({ name: p.name, used: p.used, items: p.items })), opts: st.opts, pct: st.pct }).catch(() => {});
  }
  /* المسودة ← سطر كامل الصلاحية حتى لو نقصت منه خلية */
  function hydrate(o) {
    const r = Object.assign({
      id: uid(), photoIx: 0, brandName: '', sci: '', company: '', doseV: '', doseU: '', form: '',
      packText: '', packEvidence: '', read: '', uBig: 'علبة', nMid: '', uMid: '', nSmall: '', uSmall: 'قطعة',
      stock: '', buyTop: '', saleBase: '', barcode: '', expiry: '', count: 1, confidence: 0, flags: {},
      aText: '', bText: '', saved: false, savedId: '', autoSale: false, open: false, note: '', forceNew: false,
    }, o || {});
    r.photoLost = true;
    linkRow(r);
    return r;
  }
  async function restoreDraft() {
    let d = null;
    try { d = await DB.get('meta', 'qeDraft'); } catch (_) {}
    if (!d || !Array.isArray(d.rows) || !d.rows.length) return;
    if (Date.now() - (d.ts || 0) > 86400000 * 3) { DB.del('meta', 'qeDraft').catch(() => {}); return; }
    const un = d.rows.filter(r => !r.saved).length;
    if (!un) return;
    const yes = await confirmBox(`يوجد ${un} صنفاً غير محفوظ من جلسة سابقة (${clean(d.photos && d.photos.length ? d.photos.length + ' صورة' : 'بلا صور', 40)}). استعادتها؟`, { okLabel: 'نعم، استرجع', icon: 'history' });
    if (!yes) { DB.del('meta', 'qeDraft').catch(() => {}); return; }
    st.rows = d.rows.map(r => hydrate(r));
    st.pct = d.pct != null ? d.pct : st.pct;
    Object.assign(st.opts, d.opts || {});
    st.photos = (d.photos || []).map(p => ({ id: uid(), name: clean(p.name, 60), dataUrl: '', mime: 'image/jpeg', used: !!p.used, items: p.items || 0, photoLost: true }));
    st.rows.forEach(r => { r.photoLost = true; linkRow(r); });
    drawStrip(); drawBody(); chips();
  }

  /* ───────────────────────── صندوق صور الجوال ───────────────────────── */
  function startInbox() {
    const ST = st;
    if (ST.inboxOff) return;
    let ref = null, stopped = false, chain = Promise.resolve();
    const toFile = dataUrl => {
      const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || '');
      if (!m) return null;
      const bin = atob(m[2]), arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return new File([arr], 'phone-quick.jpg', { type: m[1] });
    };
    const onPhoto = snap => { chain = chain.then(async () => {
      if (stopped) return;
      const r = snap.ref, v = snap.val() || {};
      if (v.status !== 'new') { if (Date.now() - (v.createdAt || 0) > 86400000) await r.remove(); return; }
      const claim = await r.child('status').transaction(cur => cur === 'new' ? 'processing' : undefined);
      if (!claim.committed || stopped) return;
      if (ST.photos.length >= 10) { await r.child('status').set('new'); return; }
      const f = toFile(v.image);
      if (!f) { await r.update({ status: 'failed', image: null }); return; }
      const p = await IS().prepImage(f);
      if (stopped) { await r.child('status').set('new'); return; }
      if (p) { ST.photos.push({ id: uid(), name: 'صورة جوال', dataUrl: p.dataUrl, mime: p.mime, used: false, items: 0 }); await r.update({ status: 'done', image: null }); drawStrip(); drawBody(); saveDraftSoon(); toast('وصلت صورة من الجوال إلى الإدخال السريع'); }
      else await r.update({ status: 'failed', image: null });
    }).catch(e => console.warn('quickInbox:', e)); };
    (async () => {
      while (!stopped && stage && stage.isConnected && !(typeof Sync !== 'undefined' && Sync.ready && Sync.db)) await sleep(1500);
      if (stopped || !stage || !stage.isConnected) return;
      ref = Sync.db.ref('pos/quickInbox');
      ref.on('child_added', onPhoto, e => console.warn('quickInbox:', e));
      ST.inbox = true;
    })();
    ST.inboxOff = () => { stopped = true; try { if (ref) ref.off(); } catch (_) {} ST.inboxOff = null; ST.inbox = false; };
  }

  /* ───────────────────────── الذكاء: قارئ ← قارئ ثانٍ ← قاضٍ ───────────────────────── */
  const READ_PROMPT = `You are a pharmaceutical stock-entry vision system for an Iraqi pharmacy.
The photo shows MANY medicine boxes, cartons and blister strips laid flat with their front faces visible. Extract EVERY distinct product.
Return ONLY one JSON object, nothing else:
{"items":[{"name":"","sci":"","dose_value":"","dose_unit":"","form":"","company":"","pack_text":"","pack_unit":"","strips":0,"per_strip":0,"units_per_pack":0,"barcode":"","expiry":"","count":1,"confidence":0,"read":""}]}
Hard rules:
- ONE line per DISTINCT product (same brand + same strength + same form = one line). "count" = how many identical boxes of it are visible. Never output the same product twice.
- Strength and dosage form NEVER belong inside "name": "AUGMENTIN 1G TAB" -> name:"Augmentin", dose_value:"1", dose_unit:"g", form:"Tab". "AMOXICILLIN 500MG CAPS" -> dose_value:"500", dose_unit:"mg", form:"Cap".
- A number followed by g/ml/mg right under the brand and next to a pack ("15G", "100ml", "10 TAB") is PACK SIZE or volume, never a strength of tablets.
- name: trade/brand name only, Latin letters exactly as printed, left-to-right. No company, no Arabic, no strength, no form, no pack size.
- company: manufacturer/brand owner as printed (keep its own script). sci: generic/INN name if printed, else "".
- form: exactly one of Tab, Cap, Amp, Vial, Gum, Syrup, Susp, Supp, Drops, Cream, Oint, Gel, Sachet, Spray, Inhaler, Patch, Infusion. Otherwise "".
- dose_unit: exactly one of mg, mcg, g, ml, %, IU. dose_value: digits only as a string.
- PACKING (very important): read the printed presentation carefully.
  pack_text = the exact printed packing string ("10 strips x 10 tablets", "Tab 14", "Carton of 10 strips", "علبة 20 قرص").
  strips = number of strips/blisters inside the box, per_strip = units inside one strip, units_per_pack = TOTAL small units in one box/carton as printed.
  pack_unit = the printed noun for the outer unit (carton / box / strip / blister / bottle / tube / pack).
  Put 0 wherever it is NOT printed — never invent a number here.
- barcode: only an EAN/UPC you can actually read on the box (digits only). Otherwise "".
- expiry: only if printed on a visible face, normalized "YYYY-MM" (05/2027 -> "2027-05"). A batch/lot number is NOT an expiry. Otherwise "".
- confidence: 0-100 how sure you are about that line (blurry, cut off or tiny face = below 60).
- read: the full verbatim text printed on that box, any language, max 180 chars.
Ignore hands, tables, shadows, price stickers, other photos, and any object you cannot read at least a brand name from. Never invent a product that is not in the image.
Output must start with { and end with } and contain nothing else.`;

  const JUDGE_PROMPT_HEAD = `Two independent AI readings (A and B) of ONE pharmacy photo are pasted below. You are the referee: produce the single most accurate record for every product shown, resolving the disagreements between the two readings.
Rules:
- The same product appearing in A and B is ONE output line. Keep a product that only one reading saw ONLY if it is clearly a medicine package; mark what you are unsure about.
- For every field set a status in "flags": "ok" = both readings agree, "fixed" = you chose or corrected the value, "ask" = unreadable or contradictory, the pharmacist must confirm it.
- Packing: numbers printed on the box win. When strips/per_strip/units_per_pack are missing or contradictory, look up the commercial presentation of this exact brand + company + strength + form sold in the Iraqi market and fill strips, per_strip and units_per_pack; explain the source briefly in "pack_evidence" (max 120 chars) and set flags.pack to "fixed". If you cannot verify it, set flags.pack "ask" and leave the numbers 0.
- Keep name / dose_value / dose_unit / form clean exactly as the extraction rules require (never a strength inside the name).
- barcode and expiry must NEVER be invented: if the readings do not show them, output "" and flag "ask".
- "read" is not needed. "count" = number of physical boxes visible for that line (1 when unknown).
Output ONLY JSON:
{"items":[{"name":"","sci":"","dose_value":"","dose_unit":"","form":"","company":"","pack_text":"","pack_unit":"","strips":0,"per_strip":0,"units_per_pack":0,"barcode":"","expiry":"","count":1,"confidence":0,"flags":{"name":"ok","sci":"ok","company":"ok","dose":"ok","form":"ok","pack":"ok","barcode":"ask","expiry":"ask"},"pack_evidence":""}]}
`;
  const NO_WEB = 'IMPORTANT: you have NO web access in this session. Decide only from well-established pharmaceutical market knowledge and mark anything you cannot verify as "ask". Never invent pack sizes, barcodes or expiry dates.\n\n';

  const parseJson = t => {
    const s = String(t || '').replace(/```/g, ' ');
    const a = s.indexOf('{'), b = s.lastIndexOf('}');
    if (a < 0 || b <= a) return null;
    try { return JSON.parse(s.slice(a, b + 1)); } catch (_) { return null; }
  };

  const doseUnit = v => {
    const u = clean(v, 6).replace(/[^a-zA-Zµ%]/g, '').toLowerCase();
    return u === 'iu' || u === 'ui' ? 'IU' : u === 'ug' ? 'mcg' : u === 'g' || u === 'mg' || u === 'mcg' || u === 'ml' || u === '%' ? u : '';
  };
  function normItem(o) {
    o = o && typeof o === 'object' ? o : {};
    const name = clean(o.name, 90);
    if (!name) return null;
    return {
      name, sci: clean(o.sci, 90),
      dose_value: clean(o.dose_value, 10).replace(/[^\d.]/g, ''),
      dose_unit: doseUnit(o.dose_unit),
      form: FORM_MAP[clean(o.form, 14).toLowerCase()] || clean(o.form, 20),
      company: clean(o.company, 70),
      pack_text: clean(o.pack_text, 90), pack_unit: clean(o.pack_unit, 24),
      strips: int(o.strips, 2000), per_strip: int(o.per_strip, 2000), units_per_pack: int(o.units_per_pack, 20000),
      barcode: clean(o.barcode, 24).replace(/[^0-9A-Za-z-]/g, ''),
      expiry: (IS() && IS().normExpiry(o.expiry)) || '',
      count: Math.min(400, int(o.count, 400)) || 1, confidence: Math.min(100, int(o.confidence, 100)),
      read: clean(o.read, 180),
      flags: normFlags(o.flags), pack_evidence: clean(o.pack_evidence, 140),
    };
  }
  function normFlags(f) {
    const out = {}, src = f && typeof f === 'object' ? f : {};
    Object.keys(FLAG_LABEL).forEach(k => { const v = S(src[k]).toLowerCase(); out[k] = v === 'ok' || v === 'fixed' || v === 'ask' ? v : (v === 'fix' ? 'fixed' : ''); });
    return out;
  }
  const validItems = txt => { const o = parseJson(txt); if (!o || !Array.isArray(o.items)) return null; const items = o.items.map(normItem).filter(Boolean); return items.length ? { items } : null; };
  const validJudge = txt => { const o = parseJson(txt); if (!o || !Array.isArray(o.items)) return null; const items = o.items.map(normItem).filter(Boolean); return items.length ? { items } : null; };

  function mkRow(o, photoIx) {
    const hasMid = o.strips > 0 && o.per_strip > 0;
    const total = hasMid ? o.strips * o.per_strip : (o.units_per_pack || 0);
    const outer = PACK_MAP[clean(o.pack_unit, 20).toLowerCase()] || (hasMid ? 'كرتون' : 'علبة');
    const r = {
      id: uid(), photoIx,
      brandName: clean(o.name, 90), sci: o.sci, company: o.company || '',
      doseV: o.dose_value, doseU: o.dose_unit, form: o.form,
      packText: o.pack_text, packEvidence: o.pack_evidence, read: o.read,
      uBig: outer, nMid: total ? (hasMid ? o.strips : total) : '',
      uMid: hasMid ? 'شريط' : '', nSmall: hasMid ? o.per_strip : '',
      uSmall: 'قطعة',
      stock: '', buyTop: '', saleBase: '', barcode: o.barcode || '', expiry: o.expiry || '',
      count: o.count || 1, confidence: o.confidence || 0, flags: o.flags || {},
      aText: '', bText: '', saved: false, savedId: '', autoSale: false, open: false, note: '', forceNew: false,
    };
    if (r.form && typeof FORMS !== 'undefined' && !FORMS.includes(r.form)) FORMS.push(r.form);
    if (r.company && IS()) r.company = IS().resolveCompany(r.company);
    linkRow(r);
    autoSale(r);
    return r;
  }

  /* دمج محلي بلا قاضٍ: اتفاق القارئتين = ✓، اختلاف = !، مفقود = ? */
  const core = s => clean(s, 40).toLowerCase().replace(/[^a-z0-9\u0600-\u06FF]+/g, '');
  function mergeLocal(A, B) {
    const out = A.map(a => {
      const b = B ? B.find(x => core(x.name) === core(a.name) && (x.dose_value || '') === (a.dose_value || '')) : null;
      const f = {};
      const cmp = (k, va, vb) => { f[k] = b == null ? (va ? 'ok' : 'ask') : (S(va).toLowerCase() === S(vb).toLowerCase() ? (va ? 'ok' : '') : 'fixed'); };
      cmp('name', a.name, b && b.name); cmp('sci', a.sci, b && b.sci); cmp('company', a.company, b && b.company);
      cmp('dose', a.dose_value + a.dose_unit, b && (b.dose_value + b.dose_unit)); cmp('form', a.form, b && b.form);
      cmp('barcode', a.barcode, b && b.barcode); cmp('expiry', a.expiry, b && b.expiry);
      const tot = (b && b.units_per_pack) || a.units_per_pack || (a.strips * a.per_strip);
      f.pack = a.units_per_pack || (a.strips && a.per_strip) ? 'ok' : (tot ? 'fixed' : 'ask');
      const pick = b && (b.confidence || 0) > (a.confidence || 0) ? b : a;
      return Object.assign({}, a, { strips: pick.strips || a.strips, per_strip: pick.per_strip || a.per_strip, units_per_pack: pick.units_per_pack || a.units_per_pack, pack_text: pick.pack_text || a.pack_text, pack_unit: pick.pack_unit || a.pack_unit, barcode: a.barcode || (b ? b.barcode : ''), expiry: a.expiry || (b ? b.expiry : ''), sci: a.sci || (b ? b.sci : ''), company: a.company || (b ? b.company : ''), flags: f, confidence: Math.round(((a.confidence || 0) + (b ? b.confidence || 0 : a.confidence || 0)) / (b ? 2 : 1)) });
    });
    if (B) B.forEach(b => { if (!out.some(x => core(x.name) === core(b.name) && (x.dose_value || '') === (b.dose_value || ''))) out.push(Object.assign({}, b, { flags: { name: 'ask', pack: 'ask' }, confidence: Math.round((b.confidence || 0) / 2) })); });
    return out;
  }

  const slim = it => ({ name: it.name, sci: it.sci, dose_value: it.dose_value, dose_unit: it.dose_unit, form: it.form, company: it.company, pack_text: it.pack_text, pack_unit: it.pack_unit, strips: it.strips, per_strip: it.per_strip, units_per_pack: it.units_per_pack, barcode: it.barcode, expiry: it.expiry, count: it.count, confidence: it.confidence });

  async function run() {
    if (st.busy) return;
    const todo = st.photos.filter(p => p.dataUrl);
    if (!todo.length) return toast('أضف صورة واضحة للعلبات أولاً', 'r');
    if (typeof AIHub === 'undefined') return toast('طبقة الذكاء الاصطناعي غير محمّلة', 'r');
    st.busy = true; st.cancel = new AbortController(); st.calls = 0;
    const oldRows = st.rows.slice();
    try {
      await AIHub.load();
      const all = [];
      let pi = 0;
      for (const p of todo) {
        if (st.cancel.signal.aborted) throw mkAbort();
        pi++;
        prog(`قراءة الصورة ${pi}/${todo.length} — النموذج الأول…`);
        const A = await askVision(READ_PROMPT, p.dataUrl, validItems, s => prog(`قراءة ${pi}: ` + s), 'gemini', '');
        const aItems = A.obj.items;
        p.used = true; p.reader = A.label;
        let B = null, warnB = '';
        if (st.opts.double) {
          prog(`قراءة ثانية مستقلة (${A.provider === 'gemini' ? 'بمزوّد مختلف' : 'بنموذج مختلف'})…`);
          try { B = await askVision(READ_PROMPT, p.dataUrl, validItems, s => prog('قراءة ثانية: ' + s), '', A.provider); }
          catch (e) { warnB = e.cancelled ? '' : 'تعذّرت القراءة الثانية: ' + (e.message || e); }
        }
        let items;
        if (B) {
          prog('مقارنة القراءتين وحسم الخلاف' + (st.opts.web ? ' والتحقق من التعبئة من الويب' : '') + '…');
          items = null;
          try {
            const J = await askText(JUDGE_PROMPT_HEAD + '\nA: ' + JSON.stringify({ items: aItems.map(slim) }) + '\n\nB: ' + JSON.stringify({ items: B.obj.items.map(slim) }) + '\n\nDecide now.', validJudge, s => prog('القاضي: ' + s), st.opts.web, B.provider);
            items = J.obj.items;
            st.judgeLabel = J.label;
          } catch (e) { if (!e.cancelled) items = null; else throw e; if (!items) warnB = (warnB ? warnB + ' · ' : '') + 'القاضي تعذّر — دمج محلي'; }
          if (!items) items = mergeLocal(aItems, B.obj.items);
        } else items = mergeLocal(aItems, null);
        p.items = items.length;
        items.forEach(o => { const r = mkRow(o, st.photos.indexOf(p)); r.aText = (aItems.find(x => core(x.name) === core(o.name)) || {}).read || ''; r.bText = B ? ((B.obj.items.find(x => core(x.name) === core(o.name)) || {}).read || '') : ''; r.readerA = A.label; r.readerB = B ? B.label : ''; if (warnB) r.warn = warnB; all.push(r); });
        drawStrip();
      }
      if (!all.length) throw new Error('لم يُقرأ أي صنف من الصور — جرّب صورة أقرب وأوفر إضاءة');
      st.rows = dedupeRows(oldRows.concat(all));
      chips(); saveDraft();
      toast(`قُرئ ${all.length} صنفاً — راجع الأعمدة ثم احفظ الكل`);
    } catch (e) {
      if (!st) return;
      if (e && e.cancelled) { st.rows = oldRows; toast('أُلغي التحليل'); }
      else toast('تعذّر التحليل: ' + ((e && e.message) || e), 'r');
    } finally {
      if (st) { st.busy = false; st.cancel = null; }
      prog(''); chips(); drawBody();
    }
  }

  function dedupeRows(rows) {
    const seen = new Map(), out = [];
    rows.forEach(r => {
      const k = core(r.brandName) + '|' + (r.doseV || '') + (r.doseU || '') + '|' + (r.form || '') + '|' + core(r.company) + '|' + r.photoIx;
      if (seen.has(k)) { const p = seen.get(k); p.count = (p.count || 1) + (r.count || 1); return; }
      seen.set(k, r); out.push(r);
    });
    return out;
  }

  /* ── نداء الصور ── */
  async function httpT(url, init, ms, signal) {
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), ms || 240000);
    const relay = () => ctl.abort();
    if (signal) signal.addEventListener('abort', relay);
    try {
      const res = await fetch(url, { ...init, signal: ctl.signal });
      let data = null, txt = '';
      try { txt = await res.text(); data = JSON.parse(txt); } catch (_) {}
      return { res, data, txt };
    } finally { clearTimeout(to); if (signal) signal.removeEventListener('abort', relay); }
  }
  function cls(status, msg) {
    const low = String(msg || '').toLowerCase(), o = { status, msg: clean(msg, 150) };
    if (status === 401 || (status === 403 && /(api key|authentic|invalid|forbidden|leaked|permission)/.test(low)) || (status === 400 && /(api[ _-]?key|x-api-key)/.test(low) && /(invalid|not valid|incorrect)/.test(low))) { o.keyBad = true; return o; }
    if (status === 402 || /insufficient|credit balance|out of credit|quota/.test(low)) { o.until = Date.now() + 6 * 3600000; return o; }
    if (status === 400 && /(image|vision|multimodal|modality|does not support|unsupported|content type)/.test(low)) { o.noModel = true; o.msg = 'النموذج لا يقرأ الصور'; return o; }
    if (status === 404 && /(model|not found|no longer)/.test(low)) { o.noModel = true; return o; }
    if (status === 429) { o.until = Date.now() + (/(per ?day|daily|rpd|tokens per day)/.test(low) ? 6 * 3600000 : 65000); return o; }
    if ([500, 502, 503, 504, 529].includes(status)) { o.retry = true; return o; }
    return o;
  }
  const imgParts = dataUrl => {
    const m = /^data:(image\/[a-z+]+);base64,([A-Za-z0-9+/=]+)$/i.exec(dataUrl || '');
    return m ? { mime: m[1], b64: m[2] } : null;
  };
  async function visionFetch(ent, m, prompt, dataUrl, signal) {
    const im = imgParts(dataUrl);
    if (!im) return { ok: false, status: 0, msg: 'الصورة غير صالحة' };
    const low = String(m.model).toLowerCase();
    try {
      if (m.provider === 'gemini') {
        const gen = { temperature: 0, maxOutputTokens: 16384, responseMimeType: 'application/json' };
        if (/gemini-2\.5-flash/.test(low)) gen.thinkingConfig = { thinkingBudget: 0 };
        const { res, data, txt } = await httpT(`${GB}/models/${encodeURIComponent(m.model)}:generateContent?key=${encodeURIComponent(ent.key)}`,
          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ role: 'user', parts: [{ text: prompt }, { inlineData: { mimeType: im.mime, data: im.b64 } }] }], generationConfig: gen }) }, 240000, signal);
        if (!res.ok) return Object.assign({ ok: false }, cls(res.status, (data && data.error && data.error.message) || txt));
        const c0 = (data.candidates || [])[0] || {};
        const text = (c0.content && c0.content.parts || []).map(x => x.text || '').join('');
        return text.trim() ? { ok: true, text } : { ok: false, status: 0, msg: (c0.finishReason || 'ردّ فارغ') };
      }
      if (m.provider === 'anthropic') {
        const { res, data, txt } = await httpT('https://api.anthropic.com/v1/messages', { method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': ent.key, 'anthropic-version': '2023-06-01', 'anthropic-dangerous-direct-browser-access': 'true' },
          body: JSON.stringify({ model: m.model, max_tokens: 16000, messages: [{ role: 'user', content: [{ type: 'image', source: { type: 'base64', media_type: im.mime, data: im.b64 } }, { type: 'text', text: prompt }] }] }) }, 240000, signal);
        if (!res.ok) return Object.assign({ ok: false }, cls(res.status, (data && data.error && data.error.message) || txt));
        const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text || '').join('');
        return text.trim() ? { ok: true, text } : { ok: false, status: 0, msg: 'ردّ فارغ' };
      }
      const base = BASE[m.provider];
      if (!base) return { ok: false, status: 0, msg: 'مزوّد بلا واجهة صور' };
      const hdr = { 'Content-Type': 'application/json', Authorization: 'Bearer ' + ent.key };
      if (m.provider === 'openrouter') { hdr['HTTP-Referer'] = 'https://localhost'; hdr['X-Title'] = 'DarbAlShifa POS'; }
      const { res, data, txt } = await httpT(base + '/chat/completions', { method: 'POST', headers: hdr,
        body: JSON.stringify({ model: m.model, max_tokens: 16000, messages: [{ role: 'user', content: [{ type: 'text', text: prompt }, { type: 'image_url', image_url: { url: dataUrl } }] }] }) }, 240000, signal);
      if (!res.ok) return Object.assign({ ok: false }, cls(res.status, (data && data.error && data.error.message) || txt));
      const c = (data.choices || [])[0];
      const cc = c && c.message && c.message.content;
      const text = typeof cc === 'string' ? cc : (Array.isArray(cc) ? cc.map(x => x.text || '').join('') : '');
      return text.trim() ? { ok: true, text } : { ok: false, status: 0, msg: 'ردّ فارغ' };
    } catch (e) {
      if (signal && signal.aborted) throw mkAbort();
      return { ok: false, status: 0, msg: e && e.name === 'AbortError' ? 'انتهت المهلة' : 'تعذّر الاتصال بالمزوّد' };
    }
  }

  /* مفتاح الماسح الاحتياطي (AIza في الإعدادات) إن لم تكن مفاتيح الموسوعة مضافة */
  async function localGemini() {
    const key = S(state.settings.geminiKey);
    if (!key || !IS() || !IS().usableModels) return null;
    if (localEnt && localModel) return { ent: localEnt, model: localModel };
    try {
      const used = await IS().usableModels(key);
      const withImg = (used || []).find(n => /^gemini-/.test(n) && VISION.gemini(n.toLowerCase()));
      if (!withImg) return null;
      localEnt = { id: 'local-gemini', key, provider: 'gemini', label: 'مفتاح الماسح' };
      localModel = { id: 'gemini:' + withImg, provider: 'gemini', model: withImg, score: 200, grounded: false, label: 'Gemini · ' + withImg + ' (مفتاح الماسح)', local: true };
      return { ent: localEnt, model: localModel };
    } catch (_) { return null; }
  }

  async function loop(order, invoke, validate, say) {
    const errs = [], waited = {};
    for (const m of order) {
      if (st.cancel && st.cancel.signal.aborted) throw mkAbort();
      let again = true;
      while (again) {
        again = false;
        const tried = new Set();
        const can = k => k.provider === m.provider && AIHub.canUse(k, m);
        let ent = m.local ? localEnt : AIHub.next(tried, m.id, can);
        let guard = 0;
        while (ent && guard++ < 40) {
          tried.add(ent.id);
          if (say) say(m.label + '…');
          for (let attempt = 0; attempt < 2; attempt++) {
            if (st.cancel && st.cancel.signal.aborted) throw mkAbort();
            const r = await invoke(ent, m);
            if (r.ok) {
              const v = validate(r.text);
              if (v) { st.calls++; if (!m.local) AIHub.touch(ent.id); return { obj: v, provider: m.provider, model: m.model, label: m.label }; }
              errs.push(m.model + ': ردّ غير صالح'); break;
            }
            if (r.keyBad) { if (!m.local) AIHub.markBad(ent.id, r.msg); errs.push(m.label + ': المفتاح مرفوض'); break; }
            if (r.noModel) { if (!m.local) AIHub.banPair(ent.id, m.id); errs.push(m.model + ': ' + (r.msg || 'لا يدعم')); break; }
            if (r.until) { if (!m.local) AIHub.exhaust(ent.id, m.id, r.until); errs.push(m.model + ' (' + r.status + '): حصة مستهلكة'); break; }
            errs.push(`${m.model} (${r.status || '—'}): ${r.msg || 'خطأ'}`);
            if (r.retry && attempt === 0) { await sleep(2500); continue; }
            break;
          }
          if (m.local) break;
          ent = AIHub.next(tried, m.id, can);
        }
        if (!m.local) {
          const soon = AIHub.soonest(m.id);
          if (soon && soon - Date.now() <= 130000 && (waited[m.id] || 0) < 1) {
            waited[m.id] = 1; again = true;
            if (say) say('انتظار تصفير الحد اللحظي…');
            for (let t = 0; t < 26 && soon - Date.now() > 0; t++) { if (st.cancel && st.cancel.signal.aborted) throw mkAbort(); await sleep(5000); }
          }
        }
      }
    }
    throw new Error([...new Set(errs)].slice(-5).join(' ║ ') || 'لا يوجد مفتاح جاهز');
  }

  async function visionOrder(preferPid, avoidPid) {
    await AIHub.load();
    const rank = m => (preferPid && m.provider === preferPid) ? 0 : (avoidPid && m.provider === avoidPid) ? 9 : 1;
    const order = (await AIHub.plan()).filter(m => (VISION[m.provider] || (() => false))(String(m.model).toLowerCase()));
    order.sort((a, b) => rank(a) - rank(b) || b.score - a.score);
    if (order.length) return order;
    const loc = await localGemini();
    if (loc) return [loc.model];
    throw new Error('لا يوجد نموذج صور جاهز — أضف مفتاح Gemini أو Grok أو Claude من: الإعدادات ← مفاتيح الذكاء الاصطناعي');
  }
  async function askVision(prompt, dataUrl, validate, say, preferPid, avoidPid) {
    const order = await visionOrder(preferPid, avoidPid);
    return loop(order, (ent, m) => visionFetch(ent, m, prompt, dataUrl, st.cancel ? st.cancel.signal : undefined), validate, say);
  }
  async function askText(prompt, validate, say, needWeb, avoidPid) {
    await AIHub.load();
    let order = (await AIHub.plan()).filter(m => !needWeb || m.grounded);
    if (avoidPid) order = [...order.filter(m => m.provider !== avoidPid), ...order.filter(m => m.provider === avoidPid)];
    if (!order.length) {
      const loc = await localGemini();
      if (loc) order = [loc.model];
    }
    if (!order.length) throw new Error('لا يوجد نموذج نصي جاهز للقاضٍ — أضف مفتاحاً');
    return loop(order, (ent, m) => AIHub.call(ent, m, (m.grounded ? '' : NO_WEB) + prompt), validate, say);
  }

  /* ───────────────────────── الافتتاح والإغلاق ───────────────────────── */
  async function open() {
    if (stage && stage.isConnected) { stage.focus(); return; }
    if (typeof InvoiceScanner === 'undefined') return toast('ملف الماسح غير محمّل — لازم مع الإدخال السريع', 'r');
    css();
    st = { photos: [], rows: [], busy: false, cancel: null, filter: 'all', q: '', mark: 0, calls: 0, judgeLabel: '',
      opts: { double: true, web: true }, pct: +(state.settings.profitPct ?? 30), lastNew: [], inbox: false, inboxOff: null };
    build();
    $('#modal-root').append(stage);
    document.addEventListener('paste', onPaste);
    chips(); drawStrip(); drawBody();
    stage.focus();
    if (typeof Sync !== 'undefined' && Sync.ready && Sync.db) startInbox(); else setTimeout(() => { if (stage && stage.isConnected && st && !st.inboxOff) startInbox(); }, 3000);
    restoreDraft();
  }

  async function requestClose() {
    const un = st && st.rows ? st.rows.filter(r => !r.saved).length : 0;
    if (un) {
      const yes = await confirmBox(`${un} صنفاً لم يُحفظ بعد — سيُحذف من النافذة (تبقى مسودة محلية تسترجعها لو فتحت الإدخال السريع من جديد). الإغلاق الآن؟`,
        { danger: true, okLabel: 'أغلق وحذف', icon: 'warn' });
      if (!yes) return;
    }
    forceClose();
  }
  function forceClose() {
    if (!stage) return;
    if (st && st.busy && st.cancel) st.cancel.abort();
    if (st && st.inboxOff) { try { st.inboxOff(); } catch (_) {} }
    document.removeEventListener('paste', onPaste);
    const s = stage; stage = null; els = {}; st = null; s.remove();
  }
  function isOpen() { return !!(stage && stage.isConnected); }

  return { open, close: forceClose, isOpen };
})();
