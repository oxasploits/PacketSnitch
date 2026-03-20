// See the Electron documentation for details on how to use preload scripts:
// https://www.electronjs.org/docs/latest/tutorial/process-model#preload-scripts

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("api", {
  getJsonData: () => {
    console.log("Preload: getJsonData called");
    return ipcRenderer.invoke("get-json-data");
  },
});
