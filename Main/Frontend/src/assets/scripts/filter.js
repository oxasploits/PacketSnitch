function getLeafKeys(obj) {
  const result = [];
  function recurse(current) {
    for (const key in current) {
      const value = current[key];
      if (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
      ) {
        recurse(value);
      } else {
        const uKey = key.toLowerCase().replace(/ /g, "-");
        result.push({ [key]: uKey, ["type"]: getDataType(value) });
      }
    }
  }
  recurse(obj);
  return result;
}

function searchFullKey(obj, targetKey) {
  for (const key in obj) {
    const value = obj[key];

    if (key === targetKey) {
      return value;
    }

    if (value !== null && typeof value === "object") {
      const result = searchFullKey(value, targetKey);
      if (result !== undefined) return result;
    }
  }
}
const operators = {
  "==": (a, b) => a == b,
  "!=": (a, b) => a != b,
  ">": (a, b) => a > b,
  "<": (a, b) => a < b,
  ">=": (a, b) => a >= b,
  "<=": (a, b) => a <= b,
};

function compare(a, b, operator) {
  if (!operators[operator]) {
    return operators["=="](a, b);
  }
  return operators[operator](a, b);
}

function getDataType(data) {
  function isIPv4(ip) {
    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    return ipv4Regex.test(ip);
  }
  function isHexIdentifier(str) {
    const hexRegex = /^0x[0-9a-fA-F]+$/;
    return hexRegex.test(str);
  }
  function isValidMAC(address) {
    const macRegex = /^([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}$/;
    return macRegex.test(address);
  }
  function isFloat(value) {
    return (
      typeof value === "number" &&
      !Number.isNaN(value) &&
      !Number.isInteger(value)
    );
  }
  function isInteger(value) {
    return Number.isInteger(value);
  }
  function isASCII(str) {
    return typeof str === "string" && /^[\x00-\x7F]*$/.test(str);
  }
  if (isIPv4(data)) {
    return "IP";
  }
  if (isHexIdentifier(data)) {
    return "HEX";
  }
  if (isValidMAC(data)) {
    return "MAC";
  }
  if (isFloat(data)) {
    return "FLOAT";
  }
  if (isInteger(data)) {
    return "INT";
  }
  if (isASCII(data)) {
    return "ASCII";
  } else {
    return "BIN";
  }
}

function getPacketId(packet) {
  const info = packet?.["Packet Info"];
  if (!info) return null;
  if (info["Index"] !== undefined) return info["Index"];
  if (info["Packet Processed"] !== undefined) return info["Packet Processed"];
  if (info["Packet Timestamp"] !== undefined) return info["Packet Timestamp"];
  return null;
}

function runQuery(data, query) {
  const orParts = query.split("||").map((q) => q.trim());
  const orResults = orParts.map((part) => {
    const andParts = part.split("&&").map((q) => q.trim());
    // Run first condition
    let result = filterChunk(data, andParts[0]);
    for (let i = 1; i < andParts.length; i++) {
      const nextResult = filterChunk(data, andParts[i]);
      const nextIds = new Set(nextResult.map(getPacketId));
      result = result.filter((p) => nextIds.has(getPacketId(p)));
    }
    return result;
  });

  // Combine all OR results (union, no duplicates by packet id)
  const seen = new Set();
  const combined = [];
  for (const p of orResults.flat()) {
    const id = getPacketId(p);
    const key = id !== null ? id : JSON.stringify(p);
    if (!seen.has(key)) {
      seen.add(key);
      combined.push(p);
    }
  }
  return combined;
}

function filterPackets(data, query) {
  return runQuery(data, query);
}

function filterChunk(packets, filter) {
  let hosts = JSON.parse(packets);
  let filteredPackets = [];
  for (const host in hosts["Host"]) {
    hostJson = hosts["Host"][host];
  }
  const modifiers = [">", "<", "==", "!=", ">=", "<="];
  const filterKeys = getLeafKeys(hostJson);
  const keys = filterKeys.map((k) => Object.values(k)[0]);
  const uKeys = filterKeys.map((k) => Object.keys(k)[0]);
  console.log("Available filter keys:", keys, ":", uKeys);
  let vMod, vVal;
  if (filter) {
    if (filter.includes(":")) {
      for (const host in hosts["Host"]) {
        const [key, val] = filter.split(":").map((s) => s.trim());
        if (key != "" && val != undefined) {
          if (keys.includes(key)) {
            if (modifiers.some((mod) => val.includes(mod))) {
              vMod = modifiers.find((mod) => val.includes(mod));
            }
          }
          vVal = val.replace(vMod, "").trim();
          for (const packet in hosts["Host"][host]) {
            console.log(`Filtering packets by ${key}:${val}`);
            const packetVal = searchFullKey(
              hosts["Host"][host][packet],
              uKeys[keys.indexOf(key)],
            );
            if (packetVal) {
              if (compare(packetVal, vVal, vMod)) {
                filteredPackets.push(hosts["Host"][host][packet]);
              } else {
                if (
                  getDataType(packetVal) === "ASCII" ||
                  getDataType(packetVal) === "HEX" ||
                  getDataType(packetVal) === "IP" ||
                  getDataType(packetVal) === "MAC"
                ) {
                  if (packetVal.toLowerCase() === vVal.toLowerCase()) {
                    filteredPackets.push(hosts["Host"][host][packet]);
                    break;
                  }
                }
              }
            }
          }
        } else {
          console.log(`Invalid filter key: ${key}`);
        }
      }
    }
  }
  console.log(`Filtered packets: ${filteredPackets.length}`);
  return filteredPackets;
}
module.exports = { filterPackets, getDataType };
