/* some global vars to make things easier on us */
const contentTarget = document.getElementById("json-upload");
let packets = {};
let json_cap = "";
let final_summary = "";
const status = document.getElementById("status");
let hosts = ["0.0.0.0"];
let host_filter = document.getElementById("host_filter");
let currentPacketIndex = 0;
let packetsForHost = [];
let index = 0;

/* if a json is loaded this gets our code ready */
document
  .getElementById("json-upload")
  .addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (file) {
      statusUpdate("Processing file: " + file.name);
      processFile(file);
    }
  });

/* this bilds the table if json output is selected */
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

/* processing the json comes from this */
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

/* updates to status bar come from here */
function statusUpdate(message) {
  status.textContent = message;
  setTimeout(() => {
    status.textContent = "Status: Ready";
  }, 3000);
}
/* we use this to add a single row of data on the table */
function addRow(d1, d2) {
  let ps = document.getElementById("packet_space");
  let row = ps.insertRow(-1); // We are adding at the end
  let c1 = row.insertCell(0);
  let c2 = row.insertCell(1);
  c1.innerText = d1;
  c2.innerText = d2;
}

/* this generates the table under the host data tab */
function hostPacketInfo(ip) {
  const selected = ip;
  packetsForHost = [];
  const hostPackets = packets["Host"][selected];
  for (const packet in hostPackets) {
    if (packet !== "Summary") {
      const packetData = hostPackets[packet];

      for (const key in packetData) {
        packetInfo = packetData;
        packetsForHost.push(packetInfo["Packet Info"]);
      }
    }
  }
}

/* if another host is selected we call this function */
document.getElementById("target_hosts").addEventListener("change", function () {
  const selected = document.getElementById("target_hosts").value;
  let host_filter = document.getElementById("host_filter");
  const main_panel = document.getElementById("main");
  const packet_space = document.getElementById("packet_space");
  packet_info = [];
  if (host_filter.value !== selected) {
    host_filter.value = selected;
  }
});

/* this changes the color of the tab slightly */
function highlightTab(tabId) {
  const containerDiv = document.getElementById("tab-btns");
  const allTabs = containerDiv.querySelectorAll("*");
  allTabs.forEach((tab) => {
    tab.style.backgroundColor = "#003b7a"; // Reset all tabs to default color
  });
  let tab = document.getElementById(tabId);
  tab.style.backgroundColor = "#00294a";
}

/* this runs when the analysis button is clicked */

document.getElementById("summary-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("summary-btn");
  document.getElementById("main").innerHTML =
    "<strong>Capture Analysis:</strong><br><br>" + final_summary + "<br>";
});

//     if (key === "Packet Info") {
//       const packetInfo = packetData[key];
//       for (const info in packetInfo) {
//         if (info === "IP") {
//           const ipInfo = packetInfo[info];
//           for (const ipKey in ipInfo) {
//             addRow(ipKey, ipInfo[ipKey]);
//             statusUpdate("Status: Added IP information for " + selected);
//           }
//         }
//         // everything for the therent frame goes here
//         if (info === "Ethernet Frame") {
//           const ethInfo = packetInfo[info];
//           for (const ethKey in ethInfo) {
//             if (
//               "Localnet" !=
//                 packetData["Extra Info"]["Traits"]["Network Data"][
//                   "Source IP"
//                 ]["Location"]["Location"] &&
//               "Localnet" !=
//                 packetData["Extra Info"]["Traits"]["Network Data"][
//                   "Destination IP"
//                 ]["Location"]["Location"]
//             ) {
//               addRow(
//                 "Source Location",
//                 packetData["Extra Info"]["Traits"]["Network Data"][
//                   "Source IP"
//                 ]["Location"]["Location"],
//               );
//
//               addRow(
//                 "Dest Location",
//                 packetData["Extra Info"]["Traits"]["Network Data"][
//                   "Destination IP"
//                 ]["Location"]["Location"],
//               );
//
//               addRow(ethKey, ethInfo[ethKey]);
//             }
//             statusUpdate(
//               "Status: Added Ethernet Frame information for " + selected,
//             );
//             if (info === "Raw Data") {
//               // interate over the next data and add it to the table
//             }
//           }
//         }
//         if (info === "TCP") {
//           const tcpInfo = packetInfo[info];
//           if (tcpInfo["TCP Flag Data"]) {
//             flags = tcpInfo["TCP Flag Data"]["Flags"];
//             addRow("TCP Flags", flags);
//           }
//           // iterate over the rest of hte keys in tcpInfo and add them to the table
//           if (tcpInfo["Source port"] && tcpInfo["Destination port"]) {
//             addRow("Source Port", tcpInfo["Source port"]);
//             addRow("Destination Port", tcpInfo["Destination port"]);
//             addRow("Urgent flag", tcpInfo["Urgent flag"]);
//             addRow("TCP Checksum", tcpInfo["TCP checksum"]);
//             console.log("Added TCP port information for " + selected);
//           }
//           statusUpdate("Status: Added TCP information for " + selected);
//         }
//         if (info === "Raw data") {
//           const rawData = packetInfo[info];
//           addRow("Raw Data", rawData["Payload"]["Hex Encoded"]);
//           statusUpdate(
//             "Status: Added Raw Data information for " + selected,
//           );
//         }
//       }
//     }
//     if (key === "Extra Info") {
//       const extraInfo = packetData[key];
//       for (const extraKey in extraInfo) {
//         if (extraKey === "Data Types") {
//           const dtypes = extraInfo[extraKey];
//           for (const type in dtypes) {
//             addRow("Possible data type: " + type, dtypes[type]);
//           }
//         }
//         if (extraKey === "Traits") {
//           const traits = extraInfo[extraKey];
//           if (traits["Network Data"]) {
//             addRow(
//               "Source IP Location",
//               traits["Network Data"]["Source IP"]["Location"]["Location"],
//             );
//             addRow(
//               "Destination IP Location",
//               traits["Network Data"]["Destination IP"]["Location"][
//                 "Location"
//               ],
//             );
//           }
//           for (const trait in traits) {
//             if (trait !== "Network Data" && trait !== "Server Info") {
//               addRow(trait, traits[trait]);
//             }
//             if (traits[trait]["Port Description"] !== undefined) {
//               addRow("Protocol", traits[trait]["Port Description"]);
//             }
//           }
//         }
//       }
//     }
//   }
// }
//addRow("NEXT PACKET", "******");

/* this runs when the host data button is clicked */
document.getElementById("data-btn").addEventListener("click", function () {
  highlightTab("data-btn");
  statusUpdate(
    "Status: Displaying packet information for " + host_filter.value,
  );
  document.getElementById("prev-btn").style.display = "block";
  document.getElementById("next-btn").style.display = "block";
  hostPacketInfo(host_filter.value);
  handlePacketNavigation(null);
});
//let pakinfo = hostPacketInfo(document.getElementById("host_filter").value);
//writePacketInfo("Packet Info", "Details");

document.getElementById("prev-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("prev-btn");
  hostPacketInfo(host_filter.value);
  handlePacketNavigation("prev-btn");
});

document.getElementById("next-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("next-btn");
  hostPacketInfo(host_filter.value);
  handlePacketNavigation("next-btn");
});

function handlePacketNavigation(btn) {
  if (index >= 1 && btn === "prev-btn") {
    index = index - 1;
    document.getElementById("main").innerHTML = JSON.stringify(
      packetsForHost[index],
      null,
      2,
    );
  } else {
    statusUpdate("Status: No more packets in this direction");
  }
  if (index <= packetsForHost.length + 1 && btn === "next-btn") {
    index = index + 1;
    document.getElementById("main").innerHTML = JSON.stringify(
      packetsForHost[index],
      null,
      2,
    );
  } else {
    statusUpdate("Status: No more packets in this direction");
  }
}

/* this runs when the bookmarks data button is clicked */
document.getElementById("bookmarks-btn").addEventListener("click", function () {
  highlightTab("bookmarks-btn");
  statusUpdate("Status: Syncing bookmarks... " + host_filter.value);
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
