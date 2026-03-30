const { filterPackets } = require("./filter");
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
let loaded = false;
let jsonOfPackets;
let filteredPackets;
popHexGrid("00".repeat(256));
// Set up file upload handler for JSON capture
document
  .getElementById("json-upload")
  .addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (file) {
      statusUpdate("Processing file: " + file.name);
      processFile(file);

      loaded = true;
    }
  });

document
  .getElementById("pcap-filename")
  .addEventListener("click", function (event) {
    window.getfileapi.selectFile().then((filePath) => {
      if (filePath) {
        runSnitch(filePath);
      }
    });
  });

function isValidJSON(str) {
  try {
    JSON.parse(str);
    return true;
  } catch (e) {
    return false;
  }
}

function fileLoaded(loaded) {
  if (loaded) {
    document.getElementById("tab-btns").style.opacity = "1";
    document.getElementById("prev-btn").style.opacity = "1";
    document.getElementById("next-btn").style.opacity = "1";
    document.getElementById("json-lab").style.display = "none";
    document.getElementById("pcap-lab").style.display = "none";
  } else {
    document.getElementById("json-lab").style.display = "block";
    document.getElementById("pcap-lab").style.display = "block";
  }
}

/**
 * Reads and parses the JSON file, updates UI and state.
 */
function processFile(file) {
  const reader = new FileReader();
  reader.onload = (event) => {
    const main_panel = document.getElementById("main");
    if (isValidJSON(event.target.result) == false) {
      console.log("Invalid JSON file");
      doError("Invalid JSON file, please upload a valid JSON capture!");
      fileLoaded(false);
      return;
    }
    fileLoaded(true);
    jsonOfPackets = event.target.result;
    document.getElementById("error-container").style.display = "none";
    packets = JSON.parse(event.target.result);
    json_cap = JSON.stringify(packets, null, 2);
    final_summary = packets["Final Summary"];
    if (final_summary == undefined) {
      doError("Final Summary not found in JSON!");
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
        loaded = true;

        writeSummary();
        initializeDataView();
      }
    }
  };
  reader.onerror = (error) => {
    status.textContent = "Status: Error reading file: " + error;
    doError("Error reading file!");
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
  //  document.getElementById("welcome").style.display = "The Analysis:";
  writeSummary();
});

/**
 * Displays the summary section from the loaded JSON.
 */

function writeSummary() {
  statusUpdate("Status: Displaying capture analysis summary");
  //highlightTab("summary-btn");
  if (json_cap == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
  } else {
    container = document.getElementById("main");
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("summary_content").textContent = final_summary;
    document.getElementById("summary_box").style.display = "block";
    fileLoaded(true);
  }
}

// Show host data when data button is clicked
document.getElementById("data-btn").addEventListener("click", function () {
  //highlightTab("data-btn");
  initializeDataView();
});

function initializeDataView() {
  statusUpdate(
    "Status: Displaying packet information for " + host_filter.value,
  );
  if (json_cap == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
    doError("No file loaded! Upload one of JSON or PCAP first!");
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
}

// Navigation for previous packet
document.getElementById("prev-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  //highlightTab("prev-btn");
  // hostPacketInfo(host_filter.value);
  handlePacketNavigation("prev-btn");
});

// Navigation for next packet
document.getElementById("next-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  // highlightTab("next-btn");
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
    if (host == undefined || index == undefined) {
      statusUpdate("Invalid bookmark selection, missing host or packet index");
      doError("Invalid bookmark selection, missing host or packet index!");
    } else {
      document.getElementById("target_hosts").value = host;
    }
    handlePacketNavigation("bookmark", bookmark);
  });

// Add current packet as a bookmark
document.getElementById("setBookmark").addEventListener("click", function () {
  if (document.getElementById("host_filter").value == "") {
    return;
  } else {
    curPacket = document.getElementById("host_filter").value + ":" + index;

    if (!bookmarkList.includes(curPacket)) {
      if (curPacket != undefined) {
        bookmarkList.push(curPacket);
        document
          .getElementById("selectBookmark")
          .appendChild(new Option(curPacket, curPacket));
      }
    }
  }
});

/**
 * Handles navigation between packets (next, prev, bookmark, first-load).
 * Updates UI and packet info accordingly.
 */
function handlePacketNavigation(btn, bookmark) {
  document.getElementById("loading-container").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "block";
  document.getElementById("packetPayloadPane").style.display = "block";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("welcome").style.display = "none";

  if (btn === undefined) {
    handlePacketNavigation("first-load");
  }
  packetsForHost = packets["Host"][host_filter.value];
  if (btn === "filtered") {
    packetsForHost = [];
    for (fpacket in filteredPackets) {
      pak = 0;
      for (pak in filteredPackets[fpacket]) {
        packetsForHost.push(filteredPackets[fpacket][pak]);
        host_filter.value = packetsForHost[0]["Packet Info"]["IP"]["Source IP"];
      }
    }
    index = 0;
  }
  if (btn === "bookmark") {
    if (bookmark["Host"] == undefined || bookmark["Packet"] == undefined) {
      statusUpdate("Status: Invalid bookmark data, reverting to first packet");
      doError("Invalid bookmark data, missing host or packet index!");
      handlePacketNavigation("first-load");
    } else {
      index = bookmark["Packet"];
      statusUpdate(
        "Navigating to bookmark: " + bookmark["Host"] + " packet " + index,
      );
      document.getElementById("host_filter").value = bookmark["Host"];
    }
  }
  if (!packetsForHost || packetsForHost.length === 0) {
    statusUpdate("Status: No packets found for this host");
    return;
  } else {
    if (btn === "first-load") {
      index = 0;
      "Status: Displaying packet 1 of " + packetsForHost.length;
    } else if (index >= 0 && btn === "prev-btn") {
      index--;
      statusUpdate(
        "Status: Displaying packet " + index + " of " + packetsForHost.length,
      );
    } else if (
      packetsForHost != undefined &&
      index <= packetsForHost.length &&
      btn === "next-btn"
    ) {
      index++;
      statusUpdate(
        "Status: Displaying packet " + index + " of " + packetsForHost.length,
      );
    }

    if (packetsForHost != undefined && packetsForHost[index] == undefined) {
      statusUpdate("Status: Index out of range, reverting to zero");
      index = 0;
    }
    if (
      packetsForHost != undefined &&
      (packetsForHost.length == 0 || packetsForHost[0] == undefined)
    ) {
      statusUpdate("Status: No packet information found for this host");
      document.getElementById("main").innerHTML = "Please select a json file!";
    }
    // in the data main secton, this is where we would
    // add the packet info for each packet, for now we just
    // dump the json, we'll format later
    // packetsForHost[index] is an array of all packet info
    // for the current host, we want to be able to navigate
    // through it with next and prev buttons
    if (packetsForHost == undefined || packetsForHost[index] == undefined) {
      statusUpdate("Status: No packet information found for this host");
      doError("No packet information found for this host!");
      return;
    } else {
      ip = document.getElementById("host_filter").value;
      packetDecoded = JSON.parse(JSON.stringify(packetsForHost[index]));
      console.log(packetDecoded);
      hexPayload =
        packetDecoded["Packet Info"]["Raw data"]["Payload"]["Hex Encoded"];
      infoPanel();
      popHexGrid(hexPayload);
      populateDataTypes();
    }
  }
}

function populateDataTypes() {
  list = document.getElementById("types-list");
  list.textContent = "";
  mtype = document.getElementById("mime-type");
  chars = document.getElementById("charset");
  encode = document.getElementById("encoding");
  language = document.getElementById("language");
  encode.textContent = "";
  language.textContent = "";
  encoding = "";
  lang = "";
  packetsForHost = packets["Host"][host_filter.value];
  charset = JSON.parse(
    JSON.stringify(
      packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Charset"],
    ),
  );
  if (
    packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding]"] ==
    "Unavailble for high entropy data"
  ) {
    encoding = JSON.parse(
      JSON.stringify(
        packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding"],
      ),
    );
  } else {
    encoding = JSON.stringify(
      packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding"][
        "encoding"
      ],
    );
    lang = JSON.stringify(
      packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding"][
        "language"
      ],
    );
  }

  mimet = JSON.parse(
    JSON.stringify(packetsForHost[index]["Extra Info"]["MIME Type"]),
  );
  items = JSON.parse(
    JSON.stringify(packetsForHost[index]["Extra Info"]["Data Types"]),
  );
  ssld = "";
  if (
    packetsForHost[index]["Extra Info"]["Traits"]["Server Info"][
      "Encryption Data"
    ] != "N/A" &&
    packetsForHost[index]["Extra Info"]["Traits"]["Server Info"][
      "Encryption Data"
    ] != undefined
  ) {
    ssld =
      packetsForHost[index]["Extra Info"]["Traits"]["Server Info"][
        "Encryption Data"
      ]["SSL Version"];
    proto =
      packetsForHost[index]["Extra Info"]["Traits"]["Network Data"][
        "Port Protcol"
      ];
    items = [];
    items.push(ssld + " encrypted stream");
    items.push(proto + " protocol data");
  }

  mtype.textContent = "\u03B1 MIME type: " + mimet;
  charset = charset == "" ? "Unknown" : charset;
  encoding = encoding == "" ? "Unknown" : encoding;
  if (encoding !== undefined) {
    encode.textContent =
      "\u0950 Payload Encoding: " + encoding.replace(/"/g, "");
  }
  if (lang !== undefined) {
    language.textContent = "\u03C9 Payload Language: " + lang.replace(/"/g, "");
  }
  items.forEach((item) => {
    const listItem = document.createElement("li");
    listItem.textContent = item;
    list.appendChild(listItem);
  });
}
// this takes a char code and returns true if it's
// a printable ascii character, false otherwise
function isPrintable(charCode) {
  // ASCII printable: 32 (space) to 126 (~)
  return charCode >= 32 && charCode <= 126;
}

// this changes hex to ascii
function hexToAscii(hex) {
  let ascii = "";
  for (let i = 0; i < hex.length; i += 2) {
    ascii += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return ascii;
}

// trunactes a string to a max length
function truncate(str, maxLength) {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength);
}

// returns a 0 padded hex string of a number with a given length
function decToHex(num, pad) {
  return num.toString(16).padStart(pad, "0");
}

// clears the higlights (its called after the moouse leaves grid)
function clearGridHighlights() {
  document
    .querySelectorAll(".griditem")
    .forEach((el) => el.classList.remove("highlight"));
}

/**
 * Populates the hex grid display with the given hex string.
 */
function popHexGrid(hex) {
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
      // adds only consecutive printable characters to the ascii box
      textbox.textContent += truncate(printable, 32);
      for (i = 0; i < truncate(printable, 32).length; i++) {
        highlightedHex = document.querySelectorAll(".griditem")[idx + i];
        highlightedHex.classList.add("highlight");
      }
      hexlen = parseInt(truncate(printable, 32).length, 10)
        .toString(16)
        .padStart(2, "0")
        .toUpperCase();
      hexoffset = idx.toString(16).padStart(4, "0").toUpperCase();
      if (printable.length == 0) {
        textbox.textContent = "0x" + item.textContent;
      }
      offsetbox.textContent = "0x" + hexoffset + ":" + hexlen;
    });
  });
  // this fades the box back out and calls the grid clear func
  document.querySelectorAll(".griditem").forEach((item) => {
    item.addEventListener("mouseleave", () => {
      asciibox.classList.remove("visible");
      clearGridHighlights();
    });
  });
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

// probably should break this function up into smaller pieces,
// but it works for now, it takes the current packet info and
// populates the info panel with it, including the side tables
// and the main info table, also updates the timestamp and
// ip:port info at the top
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
  sslcert = "";
  sslver = "";
  sslalgos = "";
  if (
    einfo["Traits"]["Server Info"]["Encryption Data"] == "N/A" ||
    einfo["Traits"]["Server Info"].hasOwnProperty("Encryption Data") == false
  ) {
    sslcert = "Not encrypted";
    sslver = "Not encrypted";
    sslalgos = "";
  } else {
    sslcert =
      einfo["Traits"]["Server Info"]["Encryption Data"]["SSL Cert"] ??
      "Not available";
    sslver =
      einfo["Traits"]["Server Info"]["Encryption Data"]["SSL Version"] ??
      "Not available";
    sslalgos =
      einfo["Traits"]["Server Info"]["Encryption Data"]["Encrypted With"].join(
        "<br>Extra algo info: ",
      ) ?? "No algorithm information available";
  }
  decompressed = einfo["Decompressed"]["Decompressed"];
  function removeIPs(list) {
    const ipRegex =
      /\b((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/;
    return list.filter((item) => !ipRegex.test(item));
  }

  if (einfo["Traits"]["Network Data"]["Hostnames"]["Hostnames"] == undefined) {
    dnshosts = "localhost";
  } else {
    dnshosts =
      "localhost<br>" +
      einfo["Traits"]["Network Data"]["Hostnames"]["Hostnames"].join("<br>");
  }
  newdnshosts = removeIPs(dnshosts.split("<br>")).join("<br>");
  dnshosts = newdnshosts == "" ? "localhost" : newdnshosts;

  pagetitle = einfo["Traits"]["Server Info"]["Page Title"];
  encrypted = einfo["Traits"]["Server Info"]["Encrypted"];
  proto = einfo["Traits"]["Network Data"]["Port Protcol"];
  protod = einfo["Traits"]["Network Data"]["Port Description"];
  snetclass = einfo["Traits"]["Network Data"]["Source IP"]["Class"];
  dnetclass = einfo["Traits"]["Network Data"]["Destination IP"]["Class"];
  document.getElementById("sidedatatable").textContent = "";
  document.getElementById("protoInfoSrc").textContent = "Source";
  document.getElementById("protoInfoDest").textContent = "Destination";
  document.getElementById("comp").textContent = "Unknown";
  if (decompressed == false || decompressed == undefined) {
    types = einfo["Data Types"];

    types.forEach((type) => {
      if (type.includes("Zlib") || type.includes("zlib")) {
        document.getElementById("comp").textContent = "Compressed with zlib";

        console.log("Data type identified: " + type);
      }
      if (type.includes("Gzip") || type.includes("gzip")) {
        document.getElementById("comp").textContent = "Compressed with gzip";
      }
      if (type.includes("Zip")) {
        document.getElementById("comp").textContent = "Compressed with zip";
      }
    });
  }
  if (decompressed == true && decompressed == undefined) {
    document.getElementById("comp").textContent =
      "Not regonized as compressed data";
  }
  //  wirelen
  if (pagetitle == undefined || pagetitle == "N/A") {
    document.getElementById("website").textContent =
      "Not available for this server";
  } else {
    document.getElementById("website").textContent = pagetitle;
  }
  //document.getElementById("crypt").textContent = encrypted;
  const dnsCollapsedList = dnshosts.replace(/(<br\s*\/?>\s*)+/gi, "<br>");
  document.getElementById("dns").innerHTML = dnsCollapsedList;
  if (sslalgos == undefined || sslalgos == "") {
    //document.getElementById("crypt").innerHTML = sslcert
    //  ? "Encrypted with: " + sslver + "<br>" + sslalgos
    //  : "Not Encrypted";
    document.getElementById("crypt").innerHTML = "Not encrypted";
  } else {
    document.getElementById("crypt").innerHTML =
      "Encrypted with: " + sslver + "<br>" + sslalgos;
  }

  if (proto == "Unknown") {
    document.getElementById("protocols").innerHTML = "Unknown";
  } else {
    document.getElementById("protocols").innerHTML =
      "Protocol Name: " + proto + "<br>Protocol Description: " + protod;
  }
  const chkd = [
    { name: "IP Checksum \u060F", value: ipchksum },
    { name: "TCP Checksum \u2643", value: tcpchksum },
    { name: "Flags \u0D79", value: flags },
    { name: "IP Length \u2366", value: iplayrelen },
    { name: "TCP Length \u263F", value: tcplayrelen },
    { name: "Wire Length \u2123", value: wirelen },
    { name: "Payload Length \u0905", value: payloadlen },
  ];
  const chkh = ["Protocol data", "Details"];
  createTable(chkd, chkh, "sidedatatable");
  const iph = ["Packet", "Data"];
  const ipds = [
    { name: "IP:Port \u25ce", value: sourcepair },
    { name: "MAC \u03C3", value: macsrc },
    { name: "MAC Vendor \u03b3", value: macsrcvendor },
    { name: "Network Class \u097E", value: snetclass },
  ];
  createTable(ipds, iph, "protoInfoSrc");
  const ipdd = [
    { name: "IP:Port \u25ce", value: destpair },
    { name: "MAC \u03C3", value: macdest },
    { name: "MAC Vendor \u03B3", value: macdestvendor },
    { name: "Network Class \u097E", value: dnetclass },
  ];
  createTable(ipdd, iph, "protoInfoDest");
  entropy = einfo["Traits"]["Shannon Entropy"];
  document.getElementById("timestamp").textContent = "Timestamp \u221E " + ts;
  //document.getElementById("ip2ip").textContent = sourcepair + " ~ " + destpair;
  document.getElementById("sideloctable").textContent = "";
  document.getElementById("entropybox").textContent =
    "\u096F " + entropy.toFixed(2);
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
    const nodata = [{ name: "Location \u2205", value: "Localnet" }];
    const nodatah = ["Source Host", "Location"];
    createTable(nodata, nodatah, "sideloctable");
  } else {
    const locds = [
      {
        name: "Country \u096D",
        value:
          einfo["Traits"]["Network Data"]["Source IP"]["Location"]["Country"],
      },
      {
        name: "City \u2211",
        value: einfo["Traits"]["Network Data"]["Source IP"]["Location"]["City"],
      },
      {
        name: "Timezone \u221E",
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
    const nodata = [{ name: "Location \u2205", value: "Localnet" }];
    const nodatah = ["Destination Host", "Location"];
    createTable(nodata, nodatah, "sideloctable");
  } else {
    const locdd = [
      {
        name: "Country \u096D",
        value:
          einfo["Traits"]["Network Data"]["Destination IP"]["Location"][
            "Country"
          ],
      },
      {
        name: "City \u2211",
        value:
          einfo["Traits"]["Network Data"]["Destination IP"]["Location"]["City"],
      },
      {
        name: "Timezone \u221E",

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

// the next two have hooks into IPC handlers for main.js
// data transactions

// when the main.js returns our json data from snitch.py
window.jsonapi.onJsonData((jsonData) => {
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("error-container").style.display = "none";
  statusUpdate("Loaded data from backend, processing...");
  processFile(
    new File([jsonData], "capture.json", { type: "application/json" }),
  );
  document.getElementById("loading-container").style.display = "none";
});

// here we create the backend process and hook it to the handler
function runSnitch(file) {
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("summary_content").innerHTML =
    '<span id="loaderdots" class="loading">Loading</span>';
  document.getElementById("status").textContent =
    "Status: Running snitch backend, this may take a few minutes...";
  document.getElementById("error-container").style.display = "none";

  const ret = window.snitchapi.runBackendCommand(file).then((output) => {});
}

function doError(message) {
  console.error("Error from backend:", message);
  loadcontainer = document.getElementById("loading-container");
  econtainer = document.getElementById("error-container");
  document.getElementById("summary_content").textContent = "";
  loadcontainer.style.display = "none";
  econtainer.style.display = "block";
  econtainer.textContent = message;
  econtainer.addEventListener("click", () => {
    econtainer.style.display = "none";
    loadcontainer.style.display = "none";
  });
}

document
  .getElementById("filterStr")
  .addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
      filterBy = document.getElementById("filterStr").value;
      filteredPackets = filterPackets(jsonOfPackets, filterBy);
      handlePacketNavigation("filtered", null);
    }
  });

window.onerror = (message, source, lineno, colno, error) => {
  doError(message + " at " + source + ":" + lineno + ":" + colno);
};

window.onunhandledrejection = (event) => {
  doError("Unhandled promise error! " + event.reason);
};

window.api.onError((msg) => {
  console.error("Error from backend:", msg);
  // Show alert or UI message
  doError(msg);
});

// On page load, hide packet info and payload panes
onload = function () {
  document.getElementById("selectBookmark").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("leftside").style.display = "none";
  document.getElementById("loading-container").style.display = "none";
};
