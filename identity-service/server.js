const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
const PORT = 4001;

app.use(cors());
app.use(express.json());

const JWT_SECRET =
  process.env.JWT_SECRET || "sentinelmesh-development-secret-change-later";

// Temporary in-memory storage.
// Later, each service will save its own private key locally.
const services = new Map();

/**
 * Converts a KeyObject into text format so it can be stored or returned.
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
 * Health-check endpoint.
 */
app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "SentinelMesh Identity Service",
    status: "healthy",
    registeredServices: services.size,
  });
});

/**
 * Register a service and create an Ed25519 key pair.
 *
 * Request:
 * {
 *   "serviceId": "order-service"
 * }
 */
app.post("/register", (req, res) => {
  try {
    const { serviceId } = req.body;

    if (!serviceId || typeof serviceId !== "string") {
      return res.status(400).json({
        success: false,
        error: "serviceId is required",
      });
    }

    if (services.has(serviceId)) {
      return res.status(409).json({
        success: false,
        error: "Service is already registered",
      });
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

    const publicKeyPem = exportPublicKey(publicKey);
    const privateKeyPem = exportPrivateKey(privateKey);

    services.set(serviceId, {
      serviceId,
      publicKey: publicKeyPem,
      registeredAt: new Date().toISOString(),
      active: true,
    });

    res.status(201).json({
      success: true,
      message: "Service registered successfully",
      serviceId,
      publicKey: publicKeyPem,

      // Returned only during registration.
      // In a real system, the private key must remain inside the workload.
      privateKey: privateKeyPem,
    });
  } catch (error) {
    console.error("Registration failed:", error);

    res.status(500).json({
      success: false,
      error: "Unable to register service",
    });
  }
});

/**
 * Issue a short-lived JWT for a registered service.
 *
 * Request:
 * {
 *   "serviceId": "order-service",
 *   "audience": "payment-service"
 * }
 */
app.post("/token", (req, res) => {
  try {
    const { serviceId, audience } = req.body;

    if (!serviceId || !audience) {
      return res.status(400).json({
        success: false,
        error: "serviceId and audience are required",
      });
    }

    const service = services.get(serviceId);

    if (!service) {
      return res.status(404).json({
        success: false,
        error: "Service is not registered",
      });
    }

    if (!service.active) {
      return res.status(403).json({
        success: false,
        error: "Service is inactive",
      });
    }

    const tokenId = crypto.randomUUID();

    const token = jwt.sign(
      {
        serviceId,
        audience,
        tokenId,
        tokenType: "service-access",
      },
      JWT_SECRET,
      {
        algorithm: "HS256",
        expiresIn: "5m",
        issuer: "sentinelmesh-identity-service",
        subject: serviceId,
      }
    );

    res.json({
      success: true,
      token,
      tokenId,
      serviceId,
      audience,
      expiresIn: "5 minutes",
    });
  } catch (error) {
    console.error("Token issuance failed:", error);

    res.status(500).json({
      success: false,
      error: "Unable to issue token",
    });
  }
});

/**
 * Return the registered public key of a service.
 * The proxy will use this later to verify request signatures.
 */
app.get("/services/:serviceId/public-key", (req, res) => {
  const service = services.get(req.params.serviceId);

  if (!service) {
    return res.status(404).json({
      success: false,
      error: "Service is not registered",
    });
  }

  res.json({
    success: true,
    serviceId: service.serviceId,
    publicKey: service.publicKey,
    active: service.active,
  });
});

/**
 * List registered services without exposing private keys.
 */
app.get("/services", (req, res) => {
  res.json({
    success: true,
    services: Array.from(services.values()),
  });
});

app.listen(PORT, () => {
  console.log(`Identity Service running at http://localhost:${PORT}`);
});