const { spawn } = require("child_process");
const path = require("path");

const root = path.join(__dirname, "..");

const services = [
  ["IDENTITY", "identity-service/server.js"],
  ["PROXY", "zero-trust-proxy/server.js"],
  ["USER", "services/user-service/server.js"],
  ["ORDER", "services/order-service/server.js"],
  ["PAYMENT", "services/payment-service/server.js"],
  ["DATABASE", "services/database-service/server.js"],
  ["DASHBOARD", "dashboard/server.js"],
];

const children = [];

for (const [name, relativeFile] of services) {
  const file = path.join(root, relativeFile);

  const child = spawn(process.execPath, [file], {
    cwd: root,
    stdio: ["inherit", "pipe", "pipe"],
  });

  children.push(child);

  child.stdout.on("data", (data) => {
    process.stdout.write(`[${name}] ${data}`);
  });

  child.stderr.on("data", (data) => {
    process.stderr.write(`[${name}] ${data}`);
  });

  child.on("error", (error) => {
    console.error(`[${name}] ERROR: ${error.message}`);
  });

  child.on("exit", (code) => {
    console.log(`[${name}] exited with code ${code}`);
  });
}

function stopAll() {
  console.log("\nStopping SentinelMesh services...");

  for (const child of children) {
    if (!child.killed) {
      child.kill();
    }
  }

  setTimeout(() => process.exit(0), 500);
}

process.on("SIGINT", stopAll);
process.on("SIGTERM", stopAll);

console.log("SentinelMesh services started.");