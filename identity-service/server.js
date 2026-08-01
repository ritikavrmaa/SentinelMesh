const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 4001;

app.use(cors());
app.use(express.json());

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "sentinelmesh-development-secret-change-later";

const DATA_DIRECTORY = path.join(
  __dirname,
  "data"
);

const SERVICES_FILE = path.join(
  DATA_DIRECTORY,
  "services.json"
);

const services = new Map();

/**
 * Creates the persistence folder and JSON file.
 */
function ensureStorage() {
  if (!fs.existsSync(DATA_DIRECTORY)) {
    fs.mkdirSync(DATA_DIRECTORY, {
      recursive: true,
    });
  }

  if (!fs.existsSync(SERVICES_FILE)) {
    fs.writeFileSync(
      SERVICES_FILE,
      JSON.stringify([], null, 2)
    );
  }
}

/**
 * Loads persisted service identities.
 * Only public identity information is stored here.
 */
function loadServices() {
  ensureStorage();

  try {
    const raw = fs.readFileSync(
      SERVICES_FILE,
      "utf8"
    );

    const storedServices = raw
      ? JSON.parse(raw)
      : [];

    if (!Array.isArray(storedServices)) {
      throw new Error(
        "services.json must contain an array"
      );
    }

    services.clear();

    for (const service of storedServices) {
      if (
        service.serviceId &&
        service.publicKey
      ) {
        services.set(
          service.serviceId,
          service
        );
      }
    }

    console.log(
      `Loaded ${services.size} persisted service identities`
    );
  } catch (error) {
    console.error(
      "Unable to load service identities:",
      error.message
    );

    services.clear();
  }
}

/**
 * Saves the public service registry.
 */
function saveServices() {
  ensureStorage();

  const storedServices =
    Array.from(services.values());

  const temporaryFile =
    `${SERVICES_FILE}.tmp`;

  fs.writeFileSync(
    temporaryFile,
    JSON.stringify(storedServices, null, 2)
  );

  fs.renameSync(
    temporaryFile,
    SERVICES_FILE
  );
}

/**
 * Converts KeyObjects to PEM text.
 */
function exportPublicKey(publicKey) {
  return publicKey.export({
    type: "spki",
    format: "pem",
  });
}

function exportPrivateKey(privateKey) {
  return privateKey.export({
    type: "pkcs8",
    format: "pem",
  });
}

/**
 * Health check.
 */
app.get("/health", (req, res) => {
  res.json({
    success: true,
    service:
      "SentinelMesh Identity Service",
    status: "healthy",
    persistence: "enabled",
    registeredServices: services.size,
  });
});

/**
 * Registers a service and generates an Ed25519 key pair.
 */
app.post("/register", (req, res) => {
  try {
    const serviceId =
      String(
        req.body?.serviceId || ""
      ).trim();

    if (!serviceId) {
      return res.status(400).json({
        success: false,
        error: "serviceId is required",
      });
    }

    if (services.has(serviceId)) {
      return res.status(409).json({
        success: false,
        error:
          "Service is already registered",
      });
    }

    const {
      publicKey,
      privateKey,
    } = crypto.generateKeyPairSync(
      "ed25519"
    );

    const publicKeyPem =
      exportPublicKey(publicKey);

    const privateKeyPem =
      exportPrivateKey(privateKey);

    const serviceRecord = {
      serviceId,
      publicKey: publicKeyPem,
      registeredAt:
        new Date().toISOString(),
      updatedAt:
        new Date().toISOString(),
      active: true,
    };

    services.set(
      serviceId,
      serviceRecord
    );

    saveServices();

    return res.status(201).json({
      success: true,
      message:
        "Service registered successfully",
      serviceId,
      publicKey: publicKeyPem,

      // Returned only during registration.
      privateKey: privateKeyPem,
    });
  } catch (error) {
    console.error(
      "Registration failed:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        "Unable to register service",
    });
  }
});

/**
 * Issues a short-lived service JWT.
 */
app.post("/token", (req, res) => {
  try {
    const serviceId =
      String(
        req.body?.serviceId || ""
      ).trim();

    const audience =
      String(
        req.body?.audience || ""
      ).trim();

    if (!serviceId || !audience) {
      return res.status(400).json({
        success: false,
        error:
          "serviceId and audience are required",
      });
    }

    const service =
      services.get(serviceId);

    if (!service) {
      return res.status(404).json({
        success: false,
        error:
          "Service is not registered",
      });
    }

    if (!service.active) {
      return res.status(403).json({
        success: false,
        error: "Service is inactive",
      });
    }

    const tokenId =
      crypto.randomUUID();

    const token = jwt.sign(
      {
        serviceId,
        audience,
        tokenId,
        tokenType:
          "service-access",
      },
      JWT_SECRET,
      {
        algorithm: "HS256",
        expiresIn: "5m",
        issuer:
          "sentinelmesh-identity-service",
        subject: serviceId,
      }
    );

    return res.json({
      success: true,
      token,
      tokenId,
      serviceId,
      audience,
      expiresIn: "5 minutes",
    });
  } catch (error) {
    console.error(
      "Token issuance failed:",
      error
    );

    return res.status(500).json({
      success: false,
      error: "Unable to issue token",
    });
  }
});

/**
 * Returns a service public key.
 */
app.get(
  "/services/:serviceId/public-key",
  (req, res) => {
    const service = services.get(
      req.params.serviceId
    );

    if (!service) {
      return res.status(404).json({
        success: false,
        error:
          "Service is not registered",
      });
    }

    return res.json({
      success: true,
      serviceId:
        service.serviceId,
      publicKey:
        service.publicKey,
      active: service.active,
    });
  }
);

/**
 * Lists registered public identities.
 */
app.get("/services", (req, res) => {
  return res.json({
    success: true,
    count: services.size,
    services:
      Array.from(services.values()),
  });
});

/**
 * Activates or deactivates a service identity.
 */
app.patch(
  "/services/:serviceId/status",
  (req, res) => {
    const serviceId =
      req.params.serviceId;

    const service =
      services.get(serviceId);

    if (!service) {
      return res.status(404).json({
        success: false,
        error:
          "Service is not registered",
      });
    }

    if (
      typeof req.body?.active !==
      "boolean"
    ) {
      return res.status(400).json({
        success: false,
        error:
          "active must be true or false",
      });
    }

    service.active =
      req.body.active;

    service.updatedAt =
      new Date().toISOString();

    services.set(
      serviceId,
      service
    );

    saveServices();

    return res.json({
      success: true,
      message:
        service.active
          ? "Service activated"
          : "Service deactivated",
      service,
    });
  }
);

loadServices();

app.listen(PORT, () => {
  console.log(
    `Identity Service running at http://localhost:${PORT}`
  );
  console.log(
    `Registered services: ${services.size}`
  );
  console.log(
    `Registry file: ${SERVICES_FILE}`
  );
});