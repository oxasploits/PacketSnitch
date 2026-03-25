const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const os = require("os");
const platform = os.platform();
const testcaseDir = path.join(os.tmpdir(), "testcases");
let mainWindow;
hostsFilePath = path.join(testcaseDir, "hosts.json");
// make sure we have a fresh temp dir
fs.rmdir(testcaseDir, { recursive: true }, (err) => {
  if (err) console.error(err);
});

function createWindow() {
  mainWindow = new BrowserWindow({
    minWidth: 1310,
    minHeight: 700,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
    },
    contextIsolation: true,
    nodeIntegration: false,
  });
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
}

app.whenReady().then(() => {
  createWindow();
  console.log("App ready, waiting for file selection...");
  let fileSent = false;
  // start the process that listens for the file selection and runs the backend command
  require("./back-comm");
  ipcMain.handle("select-file", async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog({
      properties: ["openFile"],
    });
    if (canceled) return null;
    console.log("Accepted pcapng.. Checking for json existence...");
    setInterval(() => {
      if (!fileSent && fs.existsSync(hostsFilePath)) {
        // here we read the file in
        const data = fs.readFileSync(hostsFilePath, "utf8");
        mainWindow.webContents.send("json-data", data);
        fileSent = true; // Prevent sending multiple times
      }
    }, 3000);
    return filePaths[0];
  });
});

app.on("before-quit", () => {
  // make sure the backend snitch process dies!
  console.log("Killing backend proc...");
  if (platform === "win32") {
    exec("taskkill /IM snitch.exe /T /F", (err) => {
      if (err) console.error(err);
    });
  }
  if (platform === "linux") {
    exec('pkill -f "snitch"', (err) => {
      if (err) console.error(err);
    });
  }
});
