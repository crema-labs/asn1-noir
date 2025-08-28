const fs = require("fs");

function stringToByteArray(str, length) {
  const arr = Array.from(str).map(
    (ch) => "0x" + ch.charCodeAt(0).toString(16).padStart(2, "0")
  );
  while (arr.length < length) arr.push("0x00");
  return arr.slice(0, length);
}

function dateToByteArray(dateStr) {
  // Example input: "250620120000Z"
  return stringToByteArray(dateStr, 16);
}

function generateProverToml(
  certificateBytes,
  rdnString,
  checkRdn,
  checkValidity,
  dateStr
) {
  const rdnBytes = stringToByteArray(rdnString, 64);
  const userDateBytes = dateToByteArray(dateStr);

  return `
certificate_bytes = [${certificateBytes.join(", ")}]
check_rdn = ${checkRdn ? "1" : "0"}
check_validity = ${checkValidity ? "1" : "0"}
rdn_first_attribute = [${rdnBytes.join(", ")}]
user_date = [${userDateBytes.join(", ")}]
  `.trim();
}

const certificateBytes = ["0x30", "0x82", "0x01", "0x0a"];
const rdnString = "Test";
const checkRdn = true;
const checkValidity = true;
const dateStr = "250620120000Z";

for (let i = certificateBytes.length; i < 512; i++) {
  certificateBytes.push("0x00"); 
}

console.log(certificateBytes.length);

const tomlContent = generateProverToml(
  certificateBytes,
  rdnString,
  checkRdn,
  checkValidity,
  dateStr
);


fs.writeFileSync("Prover.toml", tomlContent);
console.log("Prover.toml generated!");
