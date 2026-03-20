const { app, BrowserWindow } = require("electron");
//const path = require("node:path");

const CopyPlugin = require("copy-webpack-plugin");
const { ipcMain } = require("electron");
const { exec } = require("child_process");
const path = require("path");
// Handle creating/removing shortcuts on Windows when installing/uninstalling.
const fs = require("fs");
if (require("electron-squirrel-startup")) {
  app.quit();
}

const createWindow = () => {
  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 1350,
    height: 800,
    minWidth: 1310,
    minHeight: 685,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
    },
  });

  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
  // and load the index.html of the app.
  ipcMain.handle("get-json-data", async () => {
    const data = fs.readFileSync("/tmp/testcases/hosts.json", "utf8");
    mainWindow.webContents.send("get-json-data", data);

    return data;
  });

  // Open the DevTools.
  // mainWindow.webContents.openDevTools();
};

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  createWindow();

  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
