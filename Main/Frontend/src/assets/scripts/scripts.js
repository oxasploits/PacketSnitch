const contentTarget = document.getElementById("json-upload");
let packets = {};
let json_cap = "";
let final_summary = "";
const status = document.getElementById("status");
let hosts = ["0.0.0.0"];
let host_filter = document.getElementById("host_filter");
document
  .getElementById("json-upload")
  .addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (file) {
      statusUpdate("Processing file: " + file.name);
      processFile(file);
    }
  });

function writePacketInfo(h1, h2) {
  const format_selection = document.getElementById("Format").value;
  if (format_selection === "Tables") {
    const main_panel = document.getElementById("main");
    main_panel.textContent = "";
    main_panel.innerHTML =
      '<div><table class="main_panel" id="packet_space"><thead><tr><th width=25%>' +
      h1 +
      "</th><th>" +
      h2 +
      "</th></tr></thead><tbody></tbody></table></div>";
  }
  if (format_selection === "Pretty JSON") {
    main_panel.textContent = "";
    main_panel.innerHTML = '<br><pre id="json_output">' + json_cap + "</pre>";
  }
}

function processFile(file) {
  const reader = new FileReader();
  reader.onload = (event) => {
    const main_panel = document.getElementById("main");
    packets = JSON.parse(event.target.result);
    json_cap = JSON.stringify(packets, null, 2);
    final_summary = packets["Final Summary"];
    if (final_summary == undefined) {
      main_panel.textContent = "Error: Final Summary not found in JSON.";
      statusUpdate("Status: Error: Final Summary not found in JSON.");
      return;
    }
    document.getElementById("target_hosts").hidden = false;
    document.getElementById("Format").hidden = false;
    document.getElementById("summary-btn").style.display = "block";
    for (const host in packets["Host"]) {
      if (!hosts.includes(host)) {
        hosts.push(host);
        const targets_list = document.getElementById("target_hosts");
        const newhost = document.createElement("option");
        newhost.textContent = host;
        newhost.value = host;
        targets_list.appendChild(newhost);
      }
    }
  };

  reader.onerror = (error) => {
    status.textContent = "Status: Error reading file: " + error;
  };

  reader.readAsText(file);
}

function statusUpdate(message) {
  status.textContent = message;
  setTimeout(() => {
    status.textContent = "Status: Ready";
  }, 3000);
}

function addRow(d1, d2) {
  let ps = document.getElementById("packet_space");
  let row = ps.insertRow(-1); // We are adding at the end
  let c1 = row.insertCell(0);
  let c2 = row.insertCell(1);
  c1.innerText = d1;
  c2.innerText = d2;
}

function hostPacketInfo(ip) {
  const selected = ip;
  const host_filter = document.getElementById("host_filter");
  const main_panel = document.getElementById("main");
  const packet_space = document.getElementById("packet_space");
  //  for (const host in packets["Host"]) {
  const hostPackets = packets["Host"][selected];
  for (const packet in hostPackets) {
    if (packet !== "Summary") {
      const packetData = hostPackets[packet];
      for (const key in packetData) {
        if (key === "Packet Info") {
          const packetInfo = packetData[key];
          for (const info in packetInfo) {
            if (info === "IP") {
              const ipInfo = packetInfo[info];
              for (const ipKey in ipInfo) {
                addRow(ipKey, ipInfo[ipKey]);
                statusUpdate("Status: Added IP information for " + selected);
              }
            }

            if (info === "Ethernet Frame") {
              const ethInfo = packetInfo[info];
              for (const ethKey in ethInfo) {
                if (
                  "Localnet" !=
                    packetData["Extra Info"]["Traits"]["Network Data"][
                      "Source IP"
                    ]["Location"]["Location"] &&
                  "Localnet" !=
                    packetData["Extra Info"]["Traits"]["Network Data"][
                      "Destination IP"
                    ]["Location"]["Location"]
                ) {
                  addRow(
                    "Source Location",
                    packetData["Extra Info"]["Traits"]["Network Data"][
                      "Source IP"
                    ]["Location"]["Location"],
                  );
                  addRow(
                    "Dest Location",
                    packetData["Extra Info"]["Traits"]["Network Data"][
                      "Destination IP"
                    ]["Location"]["Location"],
                  );

                  addRow(ethKey, ethInfo[ethKey]);
                }
                statusUpdate(
                  "Status: Added Ethernet Frame information for " + selected,
                );
                if (info === "Raw Data") {
                  // interate over the next data and add it to the table
                }
              }
            }
            if (info === "TCP") {
              const tcpInfo = packetInfo[info];
              if (tcpInfo["TCP Flag Data"]) {
                flags = tcpInfo["TCP Flag Data"]["Flags"];
                addRow("TCP Flags", flags);
              }
              // iterate over the rest of hte keys in tcpInfo and add them to the table
              if (tcpInfo["Source port"] && tcpInfo["Destination port"]) {
                addRow("Source Port", tcpInfo["Source port"]);
                addRow("Destination Port", tcpInfo["Destination port"]);
                addRow("Urgent flag", tcpInfo["Urgent flag"]);
                addRow("TCP Checksum", tcpInfo["TCP checksum"]);
                console.log("Added TCP port information for " + selected);
              }
              statusUpdate("Status: Added TCP information for " + selected);
            }
            if (info === "Raw data") {
              const rawData = packetInfo[info];
              addRow("Raw Data", rawData["Payload"]["Hex Encoded"]);
              statusUpdate(
                "Status: Added Raw Data information for " + selected,
              );
            }
          }
        }
        if (key === "Extra Info") {
          const extraInfo = packetData[key];
          for (const extraKey in extraInfo) {
            if (extraKey === "Data Types") {
              const dtypes = extraInfo[extraKey];
              for (const type in dtypes) {
                addRow("Possible data type: " + type, dtypes[type]);
              }
            }
            if (extraKey === "Traits") {
              const traits = extraInfo[extraKey];
              if (traits["Network Data"]) {
                addRow(
                  "Source IP Location",
                  traits["Network Data"]["Source IP"]["Location"]["Location"],
                );
                addRow(
                  "Destination IP Location",
                  traits["Network Data"]["Destination IP"]["Location"][
                    "Location"
                  ],
                );
              }
              for (const trait in traits) {
                if (trait !== "Network Data" && trait !== "Server Info") {
                  addRow(trait, traits[trait]);
                }
                if (traits[trait]["Port Description"] !== undefined) {
                  addRow("Protocol", traits[trait]["Port Description"]);
                }
              }
            }
          }
        }
      }
    }
    addRow("NEXT PACKET", "******");
  }
}

document.getElementById("target_hosts").addEventListener("change", function () {
  const selected = document.getElementById("target_hosts").value;
  let host_filter = document.getElementById("host_filter");
  const main_panel = document.getElementById("main");
  const packet_space = document.getElementById("packet_space");
  if (host_filter.value !== selected) {
    host_filter.value = selected;
  }

  writePacketInfo("Packet Info", "Details");
  if (selected === "ALL hosts") {
    host_filter.value = "0.0.0.0";
    for (const ip in packets["Host"]) {
      hostPacketInfo(ip);
    }
  } else {
    hostPacketInfo(selected);
  }
});

document.getElementById("summary-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  document.getElementById("main").innerHTML =
    "<strong>Capture Analysis:</strong><br><br>" + final_summary + "<br>";
});

document.getElementById("data-btn").addEventListener("click", function () {
  statusUpdate(
    "Status: Displaying packet information for " + host_filter.value,
  );
  writePacketInfo("Packet Info", "Details");
  //let pakinfo = hostPacketInfo(document.getElementById("host_filter").value);
  //writePacketInfo("Packet Info", "Details");
  hostPacketInfo(document.getElementById("host_filter").value);
});

// Example function to run the binary
function runMyBinary() {
  // Be sure to make the path absolute
  const command = `"${path.resolve(binaryPath)}"`;

  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

// Call this function when needed, e.g., after the app is ready
app.on("ready", () => {
  // ... create window ...
  runMyBinary();
});
