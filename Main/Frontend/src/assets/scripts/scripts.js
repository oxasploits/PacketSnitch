// Global variables for DOM elements and state
const contentTarget = document.getElementById("json-upload"); // File input for JSON upload
let packets = {}; // Stores parsed packet data from JSON
let json_cap = ""; // Stringified JSON capture for pretty display
let final_summary = ""; // Stores the summary section from JSON
const status = document.getElementById("status"); // Status bar element
let hosts = ["0.0.0.0"]; // List of hosts found in capture
let host_filter = document.getElementById("host_filter"); // Host filter dropdown
let currentPacketIndex = 0; // Index of currently displayed packet
let packetsForHost = []; // Packets for the currently selected host
let index = 0; // Navigation index for packets
let bookmarkList = []; // List of bookmarks (host:packet index)
let bookmark = {}; // Current bookmark obje22
let firstRun = true; // Flag for first run to initialize hex grid

pophexgrid("00".repeat(256));

// Set up file upload handler for JSON capture
document
  .getElementById("json-upload")
  .addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (file) {
      statusUpdate("Processing file: " + file.name);
      processFile(file);
    }
  });

document
  .getElementById("pcap-filename")
  .addEventListener("click", function (event) {
    window.getfileapi.selectFile().then((filePath) => {
      if (filePath) runSnitch(filePath);
    });
  });

/**
 * Display packet info in either table or pretty JSON format,
 * depending on user selection.
 */
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

/**
 * Reads and parses the JSON file, updates UI and state.
 */
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
    // Populate host dropdown with hosts from JSON
    for (const host in packets["Host"]) {
      if (!hosts.includes(host)) {
        hosts.push(host);
        const targets_list = document.getElementById("target_hosts");
        const newhost = document.createElement("option");
        newhost.textContent = host;
        newhost.value = host;
        targets_list.appendChild(newhost);
        writeSummary();
      }
    }
  };
  reader.onerror = (error) => {
    status.textContent = "Status: Error reading file: " + error;
  };
  reader.readAsText(file);
}

/**
 * Updates the status bar with a message, then resets after 6 seconds.
 */
function statusUpdate(message) {
  status.textContent = message;
  setTimeout(() => {
    status.textContent = "Status: Ready";
  }, 6000);
}

/**
 * Loads all packets for a given host IP into packetsForHost.
 */
function hostPacketInfo(ip) {
  const selected = ip;
  packetsForHost = [];
  const hostPackets = packets["Host"][selected];
  for (const packet in hostPackets) {
    packetsForHost.push(hostPackets[packet]);
  }
}

// Update host filter when a new host is selected from dropdown
document.getElementById("target_hosts").addEventListener("change", function () {
  const selected = document.getElementById("target_hosts").value;
  let host_filter = document.getElementById("host_filter");
  packet_info = [];
  if (host_filter.value !== selected) {
    host_filter.value = selected;
  }
});

document.getElementById("target_hosts").addEventListener("click", function () {
  const selected = document.getElementById("target_hosts").value;
  handlePacketNavigation("first-load");
});
/**
 * Highlights the selected tab by changing its background color.
 */
function highlightTab(tabId) {
  const containerDiv = document.getElementById("tab-btns");
  const allTabs = containerDiv.querySelectorAll("*");
  allTabs.forEach((tab) => {
    tab.style.backgroundColor = "#003b7a"; // Reset all tabs to default color
  });
  let tab = document.getElementById(tabId);
  tab.style.backgroundColor = "#00294a";
}

// Show summary when summary button is clicked
document.getElementById("summary-btn").addEventListener("click", function () {
  document.getElementById("welcome").style.display = "The Analysis:";
  document.getElementById("welcome").style.display = "block";
  writeSummary();
});

/**
 * Displays the summary section from the loaded JSON.
 */

function writeSummary() {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("summary-btn");
  if (json_cap == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
  } else {
    container = document.getElementById("main");
    sbp = document.createElement("div");
    sbp.setAttribute("id", "summary_box");
    if (document.getElementById("summary_box") == undefined) {
      container.appendChild(sbp);
    }
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("summary_box").style.display = "none";
    sbp.innerHTML = final_summary;
    final_summary = "";
    if (firstRun) {
      document.getElementById("welcome").innerHTML = "Now Select a packet!";
      firstRun = false;
      setTimeout(() => {
        document.getElementById("summary_box").style.display = "block";
        document.getElementById("welcome").innerHTML = "The Analysis:";
      }, 8000);
    } else {
      document.getElementById("summary_box").style.display = "block";
    }
  }
}

// Show host data when data button is clicked
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
    document.getElementById("welcome").style.display = "none";
    //hostPacketInfostPacketInfo(host_filter.value);
    if (document.getElementById("host_filter").value == "") {
      document.getElementById("host_filter").value = hosts[1];
    }

    handlePacketNavigation("first-load");
  }
});

// Navigation for previous packet
document.getElementById("prev-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("prev-btn");
  //hostPacketInfo(host_filter.value);
  handlePacketNavigation("prev-btn");
});

// Navigation for next packet
document.getElementById("next-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  highlightTab("next-btn");
  //hostPacketInfo(host_filter.value);
  handlePacketNavigation("next-btn");
});

// Handle bookmark selection from dropdown
document
  .getElementById("selectBookmark")
  .addEventListener("click", function () {
    host = document.getElementById("selectBookmark").value.split(":")[0];
    index = document.getElementById("selectBookmark").value.split(":")[1];
    host_filter.value = host;
    packetsForHost = packets["Host"][host];
    bookmark["Host"] = host;
    bookmark["Packet"] = index;
    handlePacketNavigation("bookmark", bookmark);
  });

// Add current packet as a bookmark
document.getElementById("setBookmark").addEventListener("click", function () {
  curPacket = document.getElementById("host_filter").value + ":" + index;
  if (!bookmarkList.includes(curPacket)) {
    bookmarkList.push(curPacket);
    document
      .getElementById("selectBookmark")
      .appendChild(new Option(curPacket, curPacket));
  }
});

/**
 * Handles navigation between packets (next, prev, bookmark, first-load).
 * Updates UI and packet info accordingly.
 */
function handlePacketNavigation(btn, bookmark) {
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "block";
  document.getElementById("packetPayloadPane").style.display = "block";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("welcome").style.display = "none";
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
  populateDataTypes();
}

function populateDataTypes() {
  list = document.getElementById("types-list");
  list.textContent = "";
  mtype = document.getElementById("mime-type");
  chars = document.getElementById("charset");
  encode = document.getElementById("encoding");
  packetsForHost = packets["Host"][host_filter.value];
  charset = JSON.parse(
    JSON.stringify(
      packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Charset"],
    ),
  );
  encoding = JSON.parse(
    JSON.stringify(
      packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding"],
    ),
  );

  mimet = JSON.parse(
    JSON.stringify(packetsForHost[index]["Extra Info"]["MIME Type"]),
  );
  items = JSON.parse(
    JSON.stringify(packetsForHost[index]["Extra Info"]["Data Types"]),
  );
  mtype.textContent = "MIME type: " + mimet;
  charset = charset == "" ? "Unknown" : charset;
  encoding = encoding == "" ? "Unknown" : encoding;
  chars.textContent = " Payload Charset: " + charset;
  encode.textContent = "Payload Encoding: " + encoding;

  items.forEach((item) => {
    const listItem = document.createElement("li");
    listItem.textContent = item;
    list.appendChild(listItem);
  });
}
function isPrintable(charCode) {
  // ASCII printable: 32 (space) to 126 (~)
  return charCode >= 32 && charCode <= 126;
}
function hexToAscii(hex) {
  let ascii = "";
  for (let i = 0; i < hex.length; i += 2) {
    ascii += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  console.log("Converted hex to ASCII:", ascii);
  return ascii;
}
/**
 * Populates the hex grid display with the given hex string.
 */
function pophexgrid(hex) {
  asciibox = document.getElementById("payloadascii");
  // swap it back to ascii for the fade box
  ascii = hexToAscii(hex);
  document.getElementById("hexg").textContent = "";
  const container = document.getElementById("hexg");
  // this block populates the grid with boxes for hex codes
  for (x of hex.toUpperCase().match(/.{1,2}/g)) {
    const item = document.createElement("div");
    item.classList.add("griditem");
    item.textContent = x;
    container.appendChild(item);
  }
  function getPrintableSequence(startIndex) {
    let result = "";
    for (let i = startIndex; i < ascii.length; i++) {
      if (!isPrintable(ascii.charCodeAt(i))) break;
      result += String.fromCharCode(ascii.charCodeAt(i));
    }
    return result;
  }
  // Attach event listeners to each grid item
  document.querySelectorAll(".griditem").forEach((item, idx) => {
    item.addEventListener("mouseenter", () => {
      //box fade in
      offsetbox = document.getElementById("asciiOffset");
      textbox = document.getElementById("asciiText");
      asciibox.classList.add("visible");
      textbox.innerHTML = "";
      const printable = getPrintableSequence(idx);
      window.currentPrintableSequence = printable;
      item.isHighlighted = true;
      // adds only consecutive printable characters to the ascii box
      textbox.textContent += truncate(printable, 32);
      hexlen = parseInt(truncate(printable, 32).length, 10)
        .toString(16)
        .padStart(2, "0")
        .toUpperCase();

      offsetbox.textContent = "0x" + decToHex(idx, 4) + ":" + hexlen;
    });
  });
  // this fades the box back out
  document.querySelectorAll(".griditem").forEach((item) => {
    item.addEventListener("mouseleave", () => {
      asciibox.classList.remove("visible");
    });
  });
}
function truncate(str, maxLength) {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength);
}
function decToHex(num, pad) {
  return num.toString(16).padStart(pad, "0");
}

/**
 * Utility to create a table from data and headers, and append to a container.
 */
function createTable(data, headers, containerId) {
  const table = document.createElement("table");
  const headerRow = document.createElement("tr");
  headers.forEach((text) => {
    const th = document.createElement("th");
    th.textContent = text;
    headerRow.appendChild(th);
  });
  table.appendChild(headerRow);
  data.forEach((item) => {
    const row = document.createElement("tr");
    Object.values(item).forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      row.appendChild(td);
    });
    table.appendChild(row);
  });

  document.getElementById(containerId).appendChild(table);
}

/**
 * Updates the info panel with details about the current packet.
 */
function infoPanel() {
  infoPane = document.getElementById("packetInfoPane");
  document.getElementById("rightside").style.display = "block";
  document.getElementById("leftside").style.display = "block";
  infoPaneOrig = infoPane.innerHTML;
  infoPane.style.display = "block";
  p = JSON.parse(JSON.stringify(packetsForHost[index]));
  pinfo = p["Packet Info"];
  einfo = p["Extra Info"];
  ts = pinfo["Packet Timestamp"];
  ipchksum = pinfo["IP"]["IP Checksum"];
  tcpchksum = pinfo["TCP"]["TCP checksum"];
  sourcepair = pinfo["IP"]["Source IP"] + ":" + pinfo["TCP"]["Source port"];
  destpair =
    pinfo["IP"]["Destination IP"] + ":" + pinfo["TCP"]["Destination port"];
  macsrc = pinfo["Ethernet Frame"]["MAC Source"];
  macdest = pinfo["Ethernet Frame"]["MAC Destination"];
  macsrcvendor = pinfo["Ethernet Frame"]["MAC Source Vendor"];
  macdestvendor = pinfo["Ethernet Frame"]["MAC Destination Vendor"];
  flags = pinfo["TCP"]["TCP Flag Data"]["Flags"];
  iplayrelen = pinfo["IP"]["IP layer length"];
  tcplayrelen = pinfo["TCP"]["TCP layer length"];
  wirelen = pinfo["TCP"]["Wire length"];
  payloadlen = pinfo["Raw data"]["Payload Length"];
  snetclass = einfo["Traits"]["Network Data"]["Source IP"]["Class"];
  dnetclass = einfo["Traits"]["Network Data"]["Destination IP"]["Class"];
  document.getElementById("sidedatatable").textContent = "";
  document.getElementById("protoInfoSrc").textContent = "Source";
  document.getElementById("protoInfoDest").textContent = "Destination";
  const chkd = [
    { name: "IP Checksum", value: ipchksum },
    { name: "TCP Checksum", value: tcpchksum },
    { name: "Flags", value: flags },
    { name: "IP Length", value: iplayrelen },
    { name: "TCP Length", value: tcplayrelen },
    { name: "Wire Length", value: wirelen },
    { name: "Payload Length", value: payloadlen },
  ];
  const chkh = ["Protocol data", "Details"];
  createTable(chkd, chkh, "sidedatatable");
  const iph = ["Packet", "Data"];
  const ipds = [
    { name: "IP:Port", value: sourcepair },
    { name: "MAC", value: macsrc },
    { name: "MAC Vendor", value: macsrcvendor },
    { name: "Network Class", value: snetclass },
  ];
  createTable(ipds, iph, "protoInfoSrc");
  const ipdd = [
    { name: "IP:Port", value: destpair },
    { name: "MAC", value: macdest },
    { name: "MAC Vendor", value: macdestvendor },
    { name: "Network Class", value: dnetclass },
  ];
  createTable(ipdd, iph, "protoInfoDest");
  entropy = einfo["Traits"]["Shannon Entropy"];
  document.getElementById("timestamp").textContent = "Timestamp: " + ts;
  document.getElementById("ip2ip").textContent = sourcepair + " ~ " + destpair;
  document.getElementById("sideloctable").textContent = "";
  document.getElementById("entropybox").textContent = entropy.toFixed(2);
  ebox = document.getElementById("entropybox");
  if (entropy >= 6.8) {
    ebox.className = "high";
  } else if (entropy >= 4.5) {
    ebox.className = "med";
  } else {
    ebox.className = "low";
  }
  const secondColumnCells = document.querySelectorAll(
    "table tr td:nth-child(1), table tr th:nth-child(1)",
  );
  secondColumnCells.forEach((cell) => {
    cell.style.width = "23%";
  });

  //  if (snetclass == "A") {
  if (
    einfo["Traits"]["Network Data"]["Source IP"]["Location"]["City"] ==
    undefined
  ) {
    const nodata = [{ name: "Location", value: "Localnet" }];
    const nodatah = ["Source Host", "Location"];
    createTable(nodata, nodatah, "sideloctable");
  } else {
    const locds = [
      {
        name: "Country",
        value:
          einfo["Traits"]["Network Data"]["Source IP"]["Location"]["Country"],
      },
      {
        name: "City",
        value: einfo["Traits"]["Network Data"]["Source IP"]["Location"]["City"],
      },
      {
        name: "Timezone",
        value:
          einfo["Traits"]["Network Data"]["Source IP"]["Location"]["Time Zone"],
      },
    ];
    const lochs = ["Source Host", "Location"];
    createTable(locds, lochs, "sideloctable");
  }
  //  if (dnetclass == "A") {
  if (
    einfo["Traits"]["Network Data"]["Destination IP"]["Location"]["City"] ==
    undefined
  ) {
    const nodata = [{ name: "Location", value: "Localnet" }];
    const nodatah = ["Destination Host", "Location"];
    createTable(nodata, nodatah, "sideloctable");
  } else {
    const locdd = [
      {
        name: "Country",
        value:
          einfo["Traits"]["Network Data"]["Destination IP"]["Location"][
            "Country"
          ],
      },
      {
        name: "City",
        value:
          einfo["Traits"]["Network Data"]["Destination IP"]["Location"]["City"],
      },
      {
        name: "Timezone",

        value:
          einfo["Traits"]["Network Data"]["Destination IP"]["Location"][
            "Time Zone"
          ],
      },
    ];
    const lochd = ["Destination Host", "Location"];
    createTable(locdd, lochd, "sideloctable");
    //  }
  }
}

window.jsonapi.onJsonData((jsonData) => {
  processFile(
    new File([jsonData], "capture.json", { type: "application/json" }),
  );
});

function runSnitch(file) {
  window.snitchapi.runBackendCommand(file).then((output) => {
    console.log("Backend output:", output);
  });
}

// On page load, hide packet info and payload panes
onload = function () {
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("leftside").style.display = "none";
};
