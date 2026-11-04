// Install from an Electron main process you own. Does not modify DSH/VS Code itself.
import {connectEmbeddedBroker} from './native-client.mjs';

export async function installVaultHostBridge({ipcMain, webContents, discoveryFile}) {
  const client = await connectEmbeddedBroker(discoveryFile);
  const channel = 'vault:pending-secure-input';
  ipcMain.handle(channel, async event => {
    if (event.sender !== webContents || event.senderFrame !== webContents.mainFrame) {
      throw new Error('Secure input bridge unavailable');
    }
    const response = await client.pending();
    if (!Array.isArray(response.requests)) throw new Error('Invalid local request list');
    return response.requests.map(value => ({
      request_id: value.request_id, service: value.service, account: value.account,
      prompt: value.prompt, timeout_s: value.timeout_s, frame_url: value.frame_url
    }));
  });
  return () => ipcMain.removeHandler(channel);
}
