const fs = require("fs");
const { generateKeyPairSync } = require("crypto");

// Generate an RSA key pair (2048 bits)
const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "pkcs1", // "pkcs1" for .pem format
    format: "pem"
  },
  privateKeyEncoding: {
    type: "pkcs1", // "pkcs1" for .pem format
    format: "pem"
  }
});

// Save keys to files
fs.writeFileSync("./keys/accountId_1412516_private_key.pem", privateKey);
fs.writeFileSync("./keys/accountId_1412516_public_key.pem", publicKey);

console.log("✅ RSA key pair generated successfully!");
console.log("📂 Private Key: ./keys/accountId_1412516_private_key.pem");
console.log("📂 Public Key:  ./keys/accountId_1412516_public_key.pem");
console.log("\n⚠️ Upload the PUBLIC key to Cashfree Dashboard → Payout → Settings → 2FA Keys");