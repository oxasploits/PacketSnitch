const operators = {
  "==": (a, b) => a == b,
  "!=": (a, b) => a != b,
  ">=": (a, b) => a >= b,
  ">": (a, b) => a > b,
  "<=": (a, b) => a <= b,
  "<": (a, b) => a < b,
};

const compare = (a, b, op) => (operators[op] || operators["=="])(a, b);

const getPacketKey = (p) => {
  const hostKey = Object.keys(p.Host)[0];
  const packet = p.Host[hostKey][0];
  return `${hostKey}-${packet["Packet Info"]["Packet Processed"]}`;
};

const unionBy = (arr, keyFn) => {
  const map = new Map();
  for (const item of arr) map.set(keyFn(item), item);
  return [...map.values()];
};

const intersectBy = (a, b, keyFn) => {
  const setB = new Set(b.map(keyFn));
  return a.filter((item) => setB.has(keyFn(item)));
};

function getDataType(data) {
  const isIPv4 = (ip) =>
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(
      ip,
    );
  const isHex = (str) => /^0x[0-9a-fA-F]+$/.test(str);
  const isMAC = (str) => /^([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}$/.test(str);
  if (isIPv4(data)) return "IP";
  if (isHex(data)) return "HEX";
  if (isMAC(data)) return "MAC";
  if (Number.isInteger(data)) return "INT";
  if (typeof data === "number") return "FLOAT";
  if (typeof data === "string" && /^[\x00-\x7F]*$/.test(data)) return "ASCII";
  return "BIN";
}

function searchFullKey(obj, targetKey) {
  for (const key in obj) {
    if (key === targetKey) return obj[key];
    const val = obj[key];
    if (val && typeof val === "object") {
      const res = searchFullKey(val, targetKey);
      if (res !== undefined) return res;
    }
  }
}

function getLeafKeys(obj) {
  const result = [];
  const walk = (o) => {
    for (const key in o) {
      const val = o[key];

      if (val && typeof val === "object" && !Array.isArray(val)) {
        walk(val);
      } else {
        result.push({
          [key]: key.toLowerCase().replace(/ /g, "-"),
          type: getDataType(val),
        });
      }
    }
  };

  walk(obj);
  return result;
}

function filterChunk(data, filter) {
  const hosts = typeof data === "string" ? JSON.parse(data) : data;
  const results = [];
  const modifiers = [">=", "<=", ">", "<", "==", "!="];

  for (const host in hosts.Host) {
    const packets = hosts.Host[host];
    const sample = packets[0];
    const leafKeys = getLeafKeys(sample);
    const keys = leafKeys.map((k) => Object.values(k)[0]);
    const rawKeys = leafKeys.map((k) => Object.keys(k)[0]);
    if (!filter || !filter.includes(":")) continue;
    const [key, valRaw] = filter.split(":").map((s) => s.trim());
    if (!keys.includes(key)) continue;
    const mod = modifiers.find((m) => valRaw.includes(m));
    const val = valRaw.replace(mod, "").trim();
    for (const packet of packets) {
      const packetVal = searchFullKey(packet, rawKeys[keys.indexOf(key)]);
      if (packetVal === undefined) continue;
      if (mod && compare(packetVal, val, mod)) {
        results.push({ Host: { [host]: [packet] } });
        continue;
      }
      const type = getDataType(packetVal);
      if (["ASCII", "HEX", "IP", "MAC"].includes(type)) {
        if (String(packetVal).toLowerCase() === val.toLowerCase()) {
          results.push({ Host: { [host]: [packet] } });
        }
      }
    }
  }
  return results;
}

function runQuery(data, query) {
  const orParts = query.split("||").map((q) => q.trim());
  const orResults = orParts.map((part) => {
    const andParts = part.split("&&").map((q) => q.trim());
    let result = filterChunk(data, andParts[0]);
    for (let i = 1; i < andParts.length; i++) {
      const next = filterChunk(data, andParts[i]);
      result = intersectBy(result, next, getPacketKey); // ✅ FIXED
    }
    return result;
  });
  return unionBy(orResults.flat(), getPacketKey); // ✅ FIXED
}

function filterPackets(data, query) {
  let results;
  if (query.trim() === "") {
    // dummy funtion so we can return all packets in the right format
    results = runQuery(data, "wire-length:>=0"); // dummy filter that matches all packets
  } else {
    results = runQuery(data, query);
  }
  return results.map((p) => {
    const hostKey = Object.keys(p.Host)[0];
    return p.Host[hostKey][0];
  });
}

module.exports = { filterPackets };
