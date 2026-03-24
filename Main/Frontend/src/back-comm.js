const { ipcMain } = require("electron");
const { exec } = require("child_process");
ipcMain.handle("run-backend-command", async (event, filename) => {
  console.log(`Received pcap: ${filename}`);
  const command = `/usr/lib/packetsnitch/resources/backend/snitch "${filename}" -a -o /tmp/testcases`;
  //const command = `sh /usr/lib/packetsnitch/resources/backend/loader.sh`;
  console.log("Command to run:", command);
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      //      if (error) return reject(error.message);
      //     if (stderr) return reject(stderr);
      resolve(stdout);
      console.log("Backend output:", stdout);
      console.log("Backend error output:", stderr);
    });

    console.log("Backend started, watiting for JSON...");
  });
});
