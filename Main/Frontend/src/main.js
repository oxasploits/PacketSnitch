const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const os = require("os");
const platform = os.platform();
const testcaseDir = path.join(os.tmpdir(), "testcases");
let mainWindow;
let filename;
let backendLoaded = false;
if (require("electron-squirrel-startup")) {
  app.quit();
}
ipcMain.handle("file-size", async () => {
  try {
    //    const filePath = path.join(__dirname, 'path/to/your/file.txt'); // Your actual file path here

    // Get file stats asynchronously
    const stats = await fs.promises.stat(filename); // Using promises version of stat
    return stats.size; // Send back the file size
  } catch (err) {
    console.error("Error getting file stats:", err);
    return 0; // Return 0 if there's an error
  }
});

hostsFilePath = path.join(testcaseDir, "hosts.json");
// make sure we have a fresh temp dir
fs.rmSync(testcaseDir, { recursive: true, force: true }, (err) => {
  if (err) console.error(err);
});

function killBackendProcess() {
  console.log("Killing backend proc...");
  if (platform === "win32") {
    exec("taskkill /IM snitch.exe /T /F", (err) => {
      if (err) console.error(err);
    });
  }
  if (platform === "linux") {
    exec('pkill -f "testcases"', (err) => {
      if (err) console.error(err);
    });
  }
}

function killProcess() {
  console.log("Killing backend proc...");
  if (platform === "win32") {
    exec("taskkill /IM packetsnitch.exe /T /F", (err) => {
      if (err) console.error(err);
    });
  }
  if (platform === "linux") {
    exec('pkill -f "packetsnitch"', (err) => {
      if (err) console.error(err);
    });
  }
}

checkOllama().then((isInstalled) => {
  if (isInstalled) {
    console.log("Ollama is installed, proceeding with app launch...");
  } else {
    console.log(
      "Ollama is not installed. Please install Ollama to use PacketSnitch.",
    );
    killProcess();
  }
});

function createWindow() {
  mainWindow = new BrowserWindow({
    minWidth: 1180,
    minHeight: 600,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
    },
    contextIsolation: true,
    nodeIntegration: true,
  });
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
  mainWindow.webContents.on("did-finish-load", () => {
    mainWindow.webContents.setZoomFactor(0.68); // makes everything fit snuggly
  });
}

app.whenReady().then(() => {
  checkOllama().then((isInstalled) => {
    createWindow();
    app.on("activate", function () {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
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
      backendLoaded = true;
      setInterval(() => {
        if (!fileSent && fs.existsSync(hostsFilePath)) {
          // here we read the file in
          const data = fs.readFileSync(hostsFilePath, "utf8");
          mainWindow.webContents.send("json-data", data);

          fileSent = true; // Prevent sending multiple times
        }
      }, 3000);
      console.log("File selected:", filePaths[0]);
      filename = filePaths[0];
      return filePaths[0];
    });
  });
});

function checkOllama() {
  return new Promise((resolve) => {
    exec("ollama --version", (err, stdout, stderr) => {
      if (err) {
        resolve(false); // not installed or not in PATH
      } else {
        resolve(true);
      }
    });
  });
}

app.on("before-quit", () => {
  // make sure the backend snitch process dies!
  if (backendLoaded) {
    killBackendProcess();
  }
});
