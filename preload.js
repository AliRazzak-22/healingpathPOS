const { contextBridge, ipcRenderer } = require('electron');
const on = (ch, cb) => { const f = (_e, d) => cb(d); ipcRenderer.on(ch, f); return () => ipcRenderer.removeListener(ch, f); };
contextBridge.exposeInMainWorld('desktop', Object.freeze({
  minimize: () => ipcRenderer.invoke('win:minimize'),
  close:    () => ipcRenderer.invoke('win:close'),
  update: Object.freeze({
    getPending:  () => ipcRenderer.invoke('update:get'),
    download:    () => ipcRenderer.invoke('update:download'),
    ignore:      () => ipcRenderer.invoke('update:ignore'),
    onAvailable: cb => on('update:available', cb),
    onProgress:  cb => on('update:progress', cb),
    onReady:     cb => on('update:ready', cb),
    onError:     cb => on('update:error', cb),
  }),
  print: Object.freeze({
    list:   ()     => ipcRenderer.invoke('print:list'),
    silent: (opts) => ipcRenderer.invoke('print:silent', opts),
  }),
}));
