const express = require("express");
const cors = require("cors");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = 4000;
const IDENTITY_URL = "http://localhost:4001";
const PAYMENT_URL = "http://localhost:3003";

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "sentinelmesh-development-secret-change-later";

const usedNonces = new Map();

function createSigningMessage(request) {
  return [
    "POST",
    request.targetService,
    request.endpoint,
    request.timestamp,
    request.nonce,
    JSON.stringify(request.body || {}),
  ].join("\n");
}

function validateTimestamp(timestamp) {
  const requestTime = Number(timestamp);

  if (!Number.isFinite(requestTime)) {
    return false;
  }

  const difference = Math.abs(Date.now() - requestTime);

  return difference <= 30_000;
}

function isNonceUsed(nonce) {
  if (usedNonces.has(nonce)) {
    return true;
  }

  usedNonces.set(nonce, Date.now());

  setTimeout(() => {
    usedNonces.delete(nonce);
  }, 60_000);

  return false;
}

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "zero-trust-proxy",
    status: "healthy",
  });
});

app.post("/proxy/payment", async (req, res) => {
  try {
    const signedRequest = req.body;

    const {
      sourceService,
      targetService,
      endpoint,
      timestamp,
      nonce,
      accessToken,
      signature,
      body,
    } = signedRequest;

    if (
      !sourceService ||
      !targetService ||
      !endpoint ||
      !timestamp ||
      !nonce ||
      !accessToken ||
      !signature ||
      !body
    ) {
      return res.status(400).json({
        success: false,
        decision: "DENY",
        reason: "Signed request contains missing fields",
      });
    }

    if (
  targetService !== "payment-service" ||
  endpoint !== "/payments/charge"
) {
      return res.status(403).json({
        success: false,
        decision: "DENY",
        reason: "Route policy does not allow this request",
      });
    }

    if (!validateTimestamp(timestamp)) {
      return res.status(401).json({
        success: false,
        decision: "DENY",
        reason: "Request timestamp is expired or invalid",
      });
    }

    if (isNonceUsed(nonce)) {
      return res.status(409).json({
        success: false,
        decision: "DENY",
        reason: "Replay attack detected: nonce already used",
      });
    }

    let decodedToken;

    try {
      decodedToken = jwt.verify(accessToken, JWT_SECRET, {
        algorithms: ["HS256"],
      });
    } catch (error) {
      return res.status(401).json({
        success: false,
        decision: "DENY",
        reason: `Invalid access token: ${error.message}`,
      });
    }

    if (decodedToken.serviceId !== sourceService) {
      return res.status(403).json({
        success: false,
        decision: "DENY",
        reason: "Token identity does not match source service",
      });
    }

    if (decodedToken.audience !== targetService) {
      return res.status(403).json({
        success: false,
        decision: "DENY",
        reason: "Token audience does not match target service",
      });
    }

    const publicKeyResponse = await axios.get(
      `${IDENTITY_URL}/services/${encodeURIComponent(
        sourceService
      )}/public-key`
    );

    const publicKey = publicKeyResponse.data.publicKey;

    const signingMessage = createSigningMessage(signedRequest);

    const signatureValid = crypto.verify(
      null,
      Buffer.from(signingMessage),
      publicKey,
      Buffer.from(signature, "base64")
    );

    if (!signatureValid) {
      return res.status(401).json({
        success: false,
        decision: "DENY",
        reason: "Cryptographic signature verification failed",
      });
    }

    const paymentResponse = await axios.post(
      `${PAYMENT_URL}${endpoint}`,
      body
    );

    return res.json({
      success: true,
      decision: "ALLOW",
      reason: "Identity, token, signature and route policy verified",
      verifiedIdentity: sourceService,
      targetService,
      tokenId: decodedToken.tokenId,
      paymentResult: paymentResponse.data,
    });
  } catch (error) {
    console.error(
      "Proxy error:",
      error.response?.data || error.message
    );

    return res.status(500).json({
      success: false,
      decision: "DENY",
      reason:
        error.response?.data?.message ||
        error.message ||
        "Proxy verification failed",
    });
  }
});

app.listen(PORT, () => {
  console.log(`Zero-Trust Proxy running at http://localhost:${PORT}`);
});