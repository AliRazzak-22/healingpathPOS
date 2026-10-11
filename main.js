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