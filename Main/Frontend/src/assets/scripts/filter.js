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
        result.push({ [key]: uKey });
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

function filterPackets(packets, filter) {
  let hosts = JSON.parse(packets);
  let filteredPackets = [];
  for (const host in hosts["Host"]) {
    hostJson = hosts["Host"][host];
  }
  const filterKeys = getLeafKeys(hostJson);
  const keys = filterKeys.map((k) => Object.values(k)[0]);
  const uKeys = filterKeys.map((k) => Object.keys(k)[0]);
  console.log("Available filter keys:", keys, ":", uKeys);
  // leafs = getLeafKeys(hostkeys);
  //  console.log("Leaf keys in packets:", leafs[-1]);
  // need to lopp over each host in json data then get all leaf keys
  if (filter) {
    if (filter.includes(":")) {
      for (host in hosts["Host"]) {
        const [key, val] = filter.split(":").map((s) => s.trim());
        if (key != "" && val != "") {
          if (keys.includes(key)) {
            for (const packet in hosts["Host"][host]) {
              packetVal = searchFullKey(
                hosts["Host"][host],
                uKeys[keys.indexOf(key)],
              );
              if (
                packetVal &&
                packetVal.toString().toLowerCase().includes(val.toLowerCase())
              ) {
                console.log(`Filtering packets by ${key}:${val}`);
                filteredPackets.push(hosts["Host"][host]);
              }
            }
          } else {
            console.log(`Invalid filter key: ${key}`);
          }
        }
      }
    }
  }
  console.log(`Filtered packets: ${filteredPackets.length}`);
  return filteredPackets;
}
module.exports = { filterPackets };
