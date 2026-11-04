// Load only as a trusted Electron preload with contextIsolation:true, nodeIntegration:false.
const {contextBridge, ipcRenderer} = require('electron');
contextBridge.exposeInMainWorld('vaultSecureInput', Object.freeze({
  // Never accept a secret argument and never expose the broker management token.
  pending: () => ipcRenderer.invoke('vault:pending-secure-input')
}));
