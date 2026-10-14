/* Electron Main Process — نظام مبيعات صيدلية درب الشفاء */
const { app, BrowserWindow, ipcMain, Menu } = require('electron');
const path = require('path');
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
