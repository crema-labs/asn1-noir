const fs = require("fs");

const input = JSON.parse(fs.readFileSync("oids.json", "utf8"));

function toNoirBytes(str, len = 64) {
  const bytes = Array.from(Buffer.from(str));
  const padded = bytes.slice(0, len);
  while (padded.length < len) padded.push(0);
  return `[${padded.map((b) => b.toString())}]`;
}

let result = `
struct OIDInfo {
    oid: [u8; 64],
    description: [u8; 64],
    category: [u8; 64],
}

fn get_known_oids() -> [OIDInfo; ${Object.keys(input).length}] {
    [
`;

for (const [oid, { d, c }] of Object.entries(input)) {
  result += `        OIDInfo {
            oid: ${toNoirBytes(oid)},
            description: ${toNoirBytes(d)},
            category: ${toNoirBytes(c)},
        },\n`;
}

result += "    ]\n}";

fs.writeFileSync("../src/oids.nr", result);
console.log("✅ Generated src/oids.nr");
