const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("jsonapi", {
  onJsonData: (callback) => {
    ipcRenderer.on("json-data", (event, data) => {
      callback(data);
    });
  },
});

contextBridge.exposeInMainWorld("snitchapi", {
  runBackendCommand: (filename) =>
    ipcRenderer.invoke("run-backend-command", filename),
});

contextBridge.exposeInMainWorld("getfileapi", {
  selectFile: () => ipcRenderer.invoke("select-file"),
});
