const { ipcMain } = require("electron");
const { exec } = require("child_process");

ipcMain.handle("run-backend-command", async (event, filename) => {
  console.log(`Received pcap: ${filename}`);
  const command = `yes | /usr/lib/packetsnitch/resources/backend/snitch -a "${filename}"`;
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      //if (error) return reject(error.message);
      // if (stderr) return reject(stderr);
      resolve(stdout);
    });

    console.log("Backend started, watiting for JSON...");
  });
});
