const { BrowserWindow, ipcMain, app, ipcRenderer } = require("electron");
const { exec } = require("child_process");
const os = require("os");
const platform = os.platform();
const path = require("path");

tempDir = os.tmpdir();
testcasesDir = path.join(tempDir, "testcases");
ipcMain.handle("run-backend-command", async (event, filename) => {
  console.log(`Received pcap: ${filename}`);
  const isDev = !require("electron").app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../..")
    : process.resourcesPath;
  let appPath;

  if (platform === "win32") {
    appPath = path.join(basePath, "\\backend\\snitch.exe");
  }
  if (platform === "linux") {
    appPath = path.join(basePath, "/backend/snitch");
  } else {
    sendError("Unsupported platform!");
  }

  command = `"${appPath}" "${filename}" -a -o "${testcasesDir}"`;

  console.log("Command to run:", command);

  function sendError(message) {
    const win = BrowserWindow.getAllWindows()[0]; // or track your main window
    if (win) {
      win.webContents.send("backend-error", message);
    }
  }

  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      resolve(stdout);
      console.log("Backend output:", stdout);
      console.log("Backend error output:", stderr);
      if (stdout.includes("Ollama")) {
        sendError("Backend LLM generation error!");
      }
      if (error) {
        if (stderr.includes("supported capture file")) {
          sendError("Unsupported file format!");
        } else {
          sendError("Backend execution error!");
        }
      }
    });

    console.log("Backend started, watiting for JSON...");
  });
});
