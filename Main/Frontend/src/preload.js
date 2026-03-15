// See the Electron documentation for details on how to use preload scripts:
// https://www.electronjs.org/docs/latest/tutorial/process-model#preload-scripts

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  runBinary: (args) => ipcRenderer.send("run-command", args),
  handleBinaryOutput: (callback) =>
    ipcRenderer.on("binary-output", (event, ...args) => callback(...args)),
  // ...
});
