const { spawn } = require("child_process");

const services = [
  {
    name: "zero-trust-proxy",
    file: "zero-trust-proxy/server.js",
  },
  {
    name: "user-service",
    file: "services/user-service/server.js",
  },
  {
    name: "order-service",
    file: "services/order-service/server.js",
  },
  {
    name: "payment-service",
    file: "services/payment-service/server.js",
  },
];

const children = [];

function startService(service) {
  const child = spawn(process.execPath, [service.file], {
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  children.push(child);

  child.stdout.on("data", (data) => {
    process.stdout.write(`[${service.name}] ${data}`);
  });

  child.stderr.on("data", (data) => {
    process.stderr.write(`[${service.name}] ${data}`);
  });

  child.on("exit", (code, signal) => {
    console.error(
      `[${service.name}] stopped: code=${code}, signal=${signal}`
    );

    shutdown(code || 1);
  });
}

function shutdown(exitCode = 0) {
  for (const child of children) {
    if (!child.killed) {
      child.kill("SIGTERM");
    }
  }

  process.exit(exitCode);
}

for (const service of services) {
  startService(service);
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));