/* Electron Main Process — نظام مبيعات صيدلية درب الشفاء */
const { app, BrowserWindow, ipcMain, Menu, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const { autoUpdater } = require('electron-updater');

const IGNORE_MS = 15 * 60 * 1000;   // التذكير بعد التجاهل
const CHECK_MS  = 30 * 60 * 1000;   // فحص دوري
let win = null, pending = null, ignoredUntil = 0, ignoreTimer = null, downloading = false;

const trusted = e => { try { return e.senderFrame.url.startsWith('file://'); } catch { return false; } };
const send = (ch, d) => { if (win && !win.isDestroyed()) win.webContents.send(ch, d); };
const cleanNotes = n => {
  const t = typeof n === 'string' ? n : Array.isArray(n) ? n.map(x => (x && x.note) || '').join('\n') : '';
  return t.replace(/<[^>]*>/g, '').slice(0, 600);
};
function announce() { if (pending && !downloading && Date.now() >= ignoredUntil) send('update:available', pending); }
function checkNow() { if (!app.isPackaged || downloading) return; autoUpdater.checkForUpdates().catch(() => {}); } // بلا إنترنت: يُتجاهل بصمت

autoUpdater.autoDownload = false;
autoUpdater.autoInstallOnAppQuit = false;
autoUpdater.on('update-available', i => { pending = { version: i.version, notes: cleanNotes(i.releaseNotes) }; announce(); });
autoUpdater.on('update-not-available', () => { pending = null; });
autoUpdater.on('download-progress', p => send('update:progress', { percent: Math.round(p.percent) }));
autoUpdater.on('update-downloaded', () => { send('update:ready'); setTimeout(() => autoUpdater.quitAndInstall(true, true), 2000); });
autoUpdater.on('error', e => { if (downloading) { downloading = false; send('update:error', String((e && e.message) || e).slice(0, 200)); } });

ipcMain.handle('win:minimize', e => { if (trusted(e) && win) win.minimize(); });
ipcMain.handle('win:close',    e => { if (trusted(e) && win) win.close(); });
ipcMain.handle('update:get',   e => (trusted(e) && Date.now() >= ignoredUntil) ? pending : null);
ipcMain.handle('update:download', e => {
  if (!trusted(e) || !pending || downloading) return;
  downloading = true;
  autoUpdater.downloadUpdate().catch(err => { downloading = false; send('update:error', String((err && err.message) || err).slice(0, 200)); });
});
ipcMain.handle('update:ignore', e => {
  if (!trusted(e)) return;
  ignoredUntil = Date.now() + IGNORE_MS;
  clearTimeout(ignoreTimer);
  ignoreTimer = setTimeout(announce, IGNORE_MS + 500);
});

/* ═══ الطباعة الصامتة للملصقات ═══ */
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clampN = (v, lo, hi, d) => { v = +v; return isFinite(v) ? Math.min(hi, Math.max(lo, v)) : d; };
function cleanSvg(s) {
  s = String(s || '');
  if (s.length > 200000 || !/^\s*<svg[\s>]/i.test(s)) return '';
  return s.replace(/<script[\s\S]*?<\/script>/gi, '')
          .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
          .replace(/javascript:/gi, '');
}
function labelsHtml(name, code, svg, qty, w, hh) {
  const one = `<div class="l"><div class="n">${esc(name)}</div><div class="c">${svg}</div><div class="d">${esc(code)}</div></div>`;
  return `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>
@page{size:${w}mm ${hh}mm;margin:0}
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:${w}mm;background:#fff}
.l{width:${w}mm;height:${(hh - 0.3).toFixed(2)}mm;overflow:hidden;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:.6mm 1mm;page-break-after:always;break-after:page;font-family:Tahoma,Arial,sans-serif;color:#000;direction:rtl}
.l:last-child{page-break-after:auto;break-after:auto}
.n{font-size:7pt;font-weight:700;line-height:1.1;max-height:7mm;overflow:hidden;width:100%}
.c{width:100%}
.c svg{width:100%!important;height:${(hh * 0.36).toFixed(1)}mm!important;display:block}
.d{font-size:6pt;line-height:1.1;direction:ltr;letter-spacing:.5px}
</style></head><body>${one.repeat(qty)}</body></html>`;
}
ipcMain.handle('print:list', async e => {
  if (!trusted(e) || !win) return [];
  try { return await win.webContents.getPrintersAsync(); } catch { return []; }
});
ipcMain.handle('print:silent', async (e, opts) => {
  if (!trusted(e) || !win) return { ok: false, reason: 'untrusted' };
  const o = opts || {};
  const wMm = clampN(o.widthMm, 10, 200, 38), hMm = clampN(o.heightMm, 10, 200, 25);
  const qty = Math.floor(clampN(o.qty, 1, 500, 1));
  const svg = cleanSvg(o.svg);
  if (!svg) return { ok: false, reason: 'bad-barcode' };
  let deviceName = '';
  if (o.deviceName) {
    let list = []; try { list = await win.webContents.getPrintersAsync(); } catch {}
    if (!list.some(p => p.name === o.deviceName)) return { ok: false, reason: 'printer-not-found' };
    deviceName = o.deviceName;
  }
  const pw = new BrowserWindow({ show: false, width: 420, height: 320,
    webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, javascript: false } });
  try {
    const html = labelsHtml(String(o.name || '').slice(0, 120), String(o.code || '').slice(0, 64), svg, qty, wMm, hMm);
    await pw.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
    return await new Promise(res => pw.webContents.print({
      silent: true, printBackground: true, deviceName: deviceName || undefined,
      pageSize: { width: Math.round(wMm * 1000), height: Math.round(hMm * 1000) },
      margins: { marginType: 'none' }, landscape: false, scaleFactor: 100, copies: 1,
    }, (ok, reason) => res({ ok, reason: String(reason || '') })));
  } catch (err) {
    return { ok: false, reason: String((err && err.message) || err).slice(0, 120) };
  } finally { if (!pw.isDestroyed()) pw.destroy(); }
});

/* ═══ تصدير PDF — النسخ الورقية لفواتير مادة معينة ═══
   يعمل محلياً بالكامل: تُبنى صفحة HTML مؤقتة داخل مجلد مؤقّت، صورها data: فقط،
   ومحتواها مُهرَّب حرفاً حرفاً، ثم يطبعها Chromium إلى PDF وينتهي أثره لحظياً. */
const clampTxt = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n);
function safePdfName(s) {
  const base = clampTxt(s, 120)
    .replace(/[\\/:*?"<>|]+/g, '-').replace(/\.+/g, '-').replace(/-+/g, '-')
    .replace(/^[-.]+/, '').replace(/[-.\s]+$/, '').trim();
  return base || 'فواتير-ورقية-' + new Date().toISOString().slice(0, 10);
}
function pdfHtml(o) {
  const MAX_PAGES = 80, MAX_IMGS = 8, MAX_ONE = 2600000, MAX_TOTAL = 40000000;
  let budget = MAX_TOTAL;
  const pages = (Array.isArray(o.pages) ? o.pages : []).slice(0, MAX_PAGES).map(pg => {
    const head = esc(clampTxt(pg && pg.heading, 220));
    const lines = (Array.isArray(pg && pg.lines) ? pg.lines : []).slice(0, 14)
      .map(x => `<p>${esc(clampTxt(x, 320))}</p>`).join('');
    let n = 0;
    const imgs = (Array.isArray(pg && pg.images) ? pg.images : []).filter(im => {
      const mime = String((im && im.mime) || '').toLowerCase();
      const data = String((im && im.data) || '');
      if (n >= MAX_IMGS) return false;
      if (!/^image\/(jpeg|png|webp)$/.test(mime)) return false;
      if (!/^[A-Za-z0-9+/=]{120,}$/.test(data)) return false;
      if (data.length > MAX_ONE || data.length > budget) return false;
      n++; budget -= data.length; return true;
    }).map(im => `<img src="data:${String(im.mime).toLowerCase()};base64,${String(im.data)}">`).join('');
    return `<section><h2>${head}</h2>${lines}${imgs || '<p class="none">لا توجد نسخة ورقية مصوّرة لهذه القائمة</p>'}</section>`;
  }).join('');
  return `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<style>
@page{size:A4;margin:9mm}
*{box-sizing:border-box}
body{margin:0;font-family:Tahoma,'Segoe UI',Arial,sans-serif;color:#0f172a;background:#fff;direction:rtl}
.rTitle{font-size:19px;font-weight:800;margin:0 0 2mm;padding-bottom:3mm;border-bottom:2px solid #16a34a}
.rSub{font-size:11px;color:#475569;margin:0 0 6mm;font-weight:700;line-height:1.8}
section{page-break-after:always;break-after:page}
section:last-child{page-break-after:auto;break-after:auto}
h2{font-size:14px;margin:0 0 3mm;color:#065f46}
p{font-size:11.5px;margin:0 0 1.6mm;font-weight:700;color:#1e293b;line-height:1.8}
img{width:100%;max-height:212mm;object-fit:contain;border:1px solid #cbd5e1;border-radius:5px;margin:2.5mm 0 6mm;display:block}
.none{color:#b45309;background:#fef3c7;padding:6mm;border-radius:5px;font-weight:800}
</style></head><body><div class="rTitle">${esc(clampTxt(o.title, 160))}</div>
<div class="rSub">${esc(clampTxt(o.sub, 320))}</div>${pages}</body></html>`;
}
ipcMain.handle('pdf:export', async (e, o) => {
  if (!trusted(e)) return { ok: false, reason: 'untrusted' };
  const opts = (o && typeof o === 'object') ? o : {};
  if (!Array.isArray(opts.pages) || !opts.pages.length) return { ok: false, reason: 'no-pages' };
  const pw = new BrowserWindow({ show: false, width: 900, height: 1200,
    webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, javascript: false } });
  let dir = '';
  try {
    dir = fs.mkdtempSync(path.join(app.getPath('temp'), 'ds-pdf-'));
    const htmlPath = path.join(dir, 'page.html');
    fs.writeFileSync(htmlPath, pdfHtml(opts), 'utf8');
    await pw.loadFile(htmlPath);
    const buf = await pw.webContents.printToPDF({ printBackground: true, preferCSSPageSize: true, pageSize: 'A4' });
    if (!buf || !buf.length) return { ok: false, reason: 'empty-pdf' };
    const owner = (win && !win.isDestroyed()) ? win : pw;
    const r = await dialog.showSaveDialog(owner, { title: 'حفظ ملف PDF',
      defaultPath: path.join(app.getPath('downloads'), safePdfName(opts.fileName) + '.pdf'),
      filters: [{ name: 'ملف PDF', extensions: ['pdf'] }] });
    if (r.canceled || !r.filePath) return { ok: false, reason: 'canceled' };
    if (!/\.pdf$/i.test(path.extname(r.filePath))) return { ok: false, reason: 'bad-extension' };
    fs.writeFileSync(r.filePath, buf);
    shell.showItemInFolder(r.filePath);
    return { ok: true, file: r.filePath };
  } catch (err) {
    return { ok: false, reason: String((err && err.message) || err).slice(0, 160) };
  } finally {
    if (!pw.isDestroyed()) pw.destroy();
    if (dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} }
  }
});

function createWindow() {
  Menu.setApplicationMenu(null);
  win = new BrowserWindow({
    title: 'نظام مبيعات صيدلية درب الشفاء',
    fullscreen: true, show: false, backgroundColor: '#f8fafc', autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.setMenuBarVisibility(false);
  win.once('ready-to-show', () => win.show());
  win.on('restore', () => { if (!win.isFullScreen()) win.setFullScreen(true); }); // العودة من التصغير بملء الشاشة
  win.on('closed', () => { win = null; });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.loadFile(path.join(__dirname, 'index.html'));
  if (!app.isPackaged) win.webContents.openDevTools({ mode: 'detach' });
  win.webContents.once('did-finish-load', () => setTimeout(checkNow, 4000));
}

if (!app.requestSingleInstanceLock()) { app.quit(); }
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.whenReady().then(() => {
    createWindow();
    setInterval(checkNow, CHECK_MS);
    app.on('activate', () => { if (!BrowserWindow.getAllWindows().length) createWindow(); });
  });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
}
