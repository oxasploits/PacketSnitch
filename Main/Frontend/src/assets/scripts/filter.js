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
        uKey = key.toLowerCase().replace(/ /g, "-");
        result.push(uKey);
      }
    }
  }
  recurse(obj);
  return result;
}

function filterPackets(packets, filter) {
  let hosts = JSON.parse(packets);
  for (const host in hosts["Host"]) {
    hostJson = hosts["Host"][host];
  }
  const filterKeys = getLeafKeys(hostJson);
  // leafs = getLeafKeys(hostkeys);
  //  console.log("Leaf keys in packets:", leafs[-1]);
  // need to lopp over each host in json data then get all leaf keys
  if (filter) {
    if (filter.includes(":")) {
      const [key, val] = filter.split(":").map((s) => s.trim());
      if (key != "" && val != "") {
        if (filterKeys.includes(key)) {
          console.log(`Filtering packets by ${key}:${val}`);
        } else {
          console.log("Invalid filter key.");
          console.log("Available filter keys:", filterKeys);
        }
      }
    }
  }
  return;
}
module.exports = { filterPackets };
