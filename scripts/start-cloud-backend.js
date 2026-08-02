const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const credentialFiles = [
  {
    name: "user-service",
    envName: "USER_SERVICE_IDENTITY_B64",
    file: "services/user-service/credentials/identity.json",
  },
  {
    name: "order-service",
    envName: "ORDER_SERVICE_IDENTITY_B64",
    file: "services/order-service/credentials/identity.json",
  },
  {
    name: "payment-service",
    envName: "PAYMENT_SERVICE_IDENTITY_B64",
    file: "services/payment-service/credentials/identity.json",
  },
];

function restoreCredentials() {
  for (const credential of credentialFiles) {
    const encoded = process.env[credential.envName];

    // Local development already has these files.
    if (!encoded && fs.existsSync(credential.file)) {
      console.log(
        `[bootstrap] Using existing credentials for ${credential.name}`
      );
      continue;
    }

    if (!encoded) {
      throw new Error(
        `Missing Railway variable: ${credential.envName}`
      );
    }

    const absolutePath = path.resolve(credential.file);

    fs.mkdirSync(path.dirname(absolutePath), {
      recursive: true,
    });

    fs.writeFileSync(
      absolutePath,
      Buffer.from(encoded, "base64")
    );

    console.log(
      `[bootstrap] Restored credentials for ${credential.name}`
    );
  }
}

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

function shutdown(exitCode = 0) {
  for (const child of children) {
    if (!child.killed) {
      child.kill("SIGTERM");
    }
  }

  process.exit(exitCode);
}

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

try {
  restoreCredentials();

  for (const service of services) {
    startService(service);
  }
} catch (error) {
  console.error(`[bootstrap] ${error.message}`);
  process.exit(1);
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));