const { ipcMain, app, ipcRenderer } = require("electron");
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
  let backendChild;

  if (platform === "win32") {
    appPath = path.join(basePath, "\\backend\\snitch.exe");
  }
  if (platform === "linux") {
    appPath = path.join(basePath, "/backend/snitch");
  }

  command = `"${appPath}" "${filename}" -a -o "${testcasesDir}"`;

  console.log("Command to run:", command);

  return new Promise((resolve, reject) => {
    backendChild = exec(command, (error, stdout, stderr) => {
      resolve(stdout);
      console.log("Backend output:", stdout);
      console.log("Backend error output:", stderr);
    });

    console.log("Backend started, watiting for JSON...");
  });
});
