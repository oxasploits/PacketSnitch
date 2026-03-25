const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const fs = require("fs");
const path = require("path");
const process = require("process");
const { exec } = require('child_process');

const os = require("os");
const platform = os.platform();
const testcaseDir = path.join(os.tmpdir(), "testcases")
let mainWindow;
hostsFilePath = "";
hostsFilePath = path.join(testcaseDir, "hosts.json");

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
  let fileSent = false;
  // this function handles polling for the existence of the json
  require("./back-comm");
  // remove the tmp directory on startup to ensure we have a clean directory
  // if a pcap file is opened, then we start polling for the
  //json file to be created by the backend, and send it to the
  // back-comm process to start the snitch.py backend.
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



app.on('before-quit', () => {
  // make sure the backend snitch process dies!
  console.log("Killing backend proc...");
  exec('taskkill /IM snitch.exe /T /F', (err) => {
  if (err) console.error(err);
});

exec('pkill -f "snitch"', (err) => {
  if (err) console.error(err);
});

});

