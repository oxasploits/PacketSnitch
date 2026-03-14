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
let bookmarkList = [];

let bookmark = {};
/* if a json is loaded this gets our code ready */
pophexgrid("00".repeat(256));
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
  }, 6000);
}

/* this generates the table under the host data tab */
function hostPacketInfo(ip) {
  const selected = ip;
  packetsForHost = [];
  const hostPackets = packets["Host"][selected];
  for (const packet in hostPackets) {
    packetsForHost.push(hostPackets[packet]);
  }
}

/* if another host is selected we call this function */
document.getElementById("target_hosts").addEventListener("change", function () {
  const selected = document.getElementById("target_hosts").value;
  let host_filter = document.getElementById("host_filter");
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
  writeSummary();
});

function writeSummary() {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("summary-btn");
  if (json_cap == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
  } else {
    container = document.getElementById("main");
    sbp = document.createElement("div");
    sbp.setAttribute("id", "summary_box");
    container.appendChild(sbp);
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("summary_box").style.display = "block";
    sbp.innerHTML = final_summary;
    final_summary = "";
  }
}

/* this runs when the host data button is clicked */
document.getElementById("data-btn").addEventListener("click", function () {
  highlightTab("data-btn");
  statusUpdate(
    "Status: Displaying packet information for " + host_filter.value,
  );
  if (json_cap == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
  } else {
    document.getElementById("prev-btn").style.display = "block";
    document.getElementById("next-btn").style.display = "block";
    //hostPacketInfostPacketInfo(host_filter.value);
    handlePacketNavigation("first-load");
  }
});
//let pakinfo = hostPacketInfo(document.getElementById("host_filter").value);
//writePacketInfo("Packet Info", "Details");

document.getElementById("prev-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("prev-btn");
  //hostPacketInfo(host_filter.value);
  handlePacketNavigation("prev-btn");
});
document.getElementById("next-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("next-btn");
  //hostPacketInfo(host_filter.value);
  handlePacketNavigation("next-btn");
});

document
  .getElementById("selectBookmark")
  .addEventListener("change", function () {
    host = document.getElementById("selectBookmark").value.split(":")[0];
    index = document.getElementById("selectBookmark").value.split(":")[1];
    host_filter.value = host;
    packetsForHost = packets["Host"][host];
    bookmark["Host"] = host;
    bookmark["Packet"] = index;
    handlePacketNavigation("bookmark", bookmark);
  });

document.getElementById("setBookmark").addEventListener("click", function () {
  curPacket = document.getElementById("host_filter").value + ":" + index;
  if (!bookmarkList.includes(curPacket)) {
    bookmarkList.push(curPacket);
    document
      .getElementById("selectBookmark")
      .appendChild(new Option(curPacket, curPacket));
  }
});

function handlePacketNavigation(btn, bookmark) {
  document.getElementById("packetInfoPane").style.display = "block";
  document.getElementById("packetPayloadPane").style.display = "block";
  document.getElementById("summary_box").style.display = "none";
  if (btn === undefined) {
    handlePacketNavigation("first-load");
  }
  packetsForHost = packets["Host"][host_filter.value];
  if (btn === "bookmark") {
    index = bookmark["Packet"];
    document.getElementById("host_filter").value = bookmark["Host"];
  }

  if (btn === "first-load") {
    index = 0;
    "Status: Displaying packet 1 of " + packetsForHost.length;
  } else if (index >= 0 && btn === "prev-btn") {
    index--;
    statusUpdate(
      "Status: Displaying packet " + index + " of " + packetsForHost.length,
    );
  } else if (index <= packetsForHost.length && btn === "next-btn") {
    index++;
    statusUpdate(
      "Status: Displaying packet " + index + " of " + packetsForHost.length,
    );
  } else {
    statusUpdate("Status: No more packets in this direction");
  }
  if (packetsForHost[index] == undefined) {
    statusUpdate("Status: Index out of range, reverting to zero");
    index = 0;
  }
  if (packetsForHost.length == 0 || packetsForHost[0] == undefined) {
    statusUpdate("Status: No packet information found for this host");
    document.getElementById("main").innerHTML = "Please select a json file!";
  }
  /* in the data main secton, this is where we would 
    add the packet info for each packet, for now we just
    dump the json, we'll format later 
   
   packetsForHost[index] is an array of all packet info 
   for the current host, we want to be able to navigate
   through it with next and prev buttons */
  ip = document.getElementById("host_filter").value;
  packetDecoded = JSON.parse(JSON.stringify(packetsForHost[index]));
  hexPayload =
    packetDecoded["Packet Info"]["Raw data"]["Payload"]["Hex Encoded"];
  infoPanel();
  pophexgrid(hexPayload);
}

function pophexgrid(hex) {
  document.getElementById("hexg").textContent = "";
  const container = document.getElementById("hexg");
  for (x of hex.toUpperCase().match(/.{1,2}/g)) {
    const item = document.createElement("div");
    item.classList.add("griditem");
    item.textContent = x;
    container.appendChild(item);
  }
}

function infoPanel() {
  p = JSON.parse(JSON.stringify(packetsForHost[index]));
  pinfo = p["Packet Info"];
  ts = pinfo["Packet Timestamp"];
  ipchksum = pinfo["IP"]["IP Checksum"];
  tcpchksum = pinfo["TCP"]["TCP checksum"];
  infoPane = document.getElementById("packetInfoPane");
  infoPane.innerHTML = "<strong>Packet Timestamp:</strong>" + ts + "<br>";
  infoPane.innerHTML += "<strong>Checksums</strong><br>";
  infoPane.innerHTML +=
    "<strong>IP </strong>" +
    ipchksum +
    "<strong> | TCP </strong>" +
    tcpchksum +
    "<br>";
}

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

onload = function () {
  writeSummary();
};
