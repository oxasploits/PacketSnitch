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

contextBridge.exposeInMainWorld("api", {
  onError: (callback) => {
    ipcRenderer.on("backend-error", (_event, message) => {
      callback(message);
    });
  },
});

contextBridge.exposeInMainWorld("goodmsg", {
  getGoodMsg: () => ipcRenderer.invoke("good-msg"), // Expose this method to renderer
});
