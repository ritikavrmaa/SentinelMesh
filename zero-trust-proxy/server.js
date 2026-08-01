const express = require("express");
const cors = require("cors");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { randomUUID } = require("crypto");

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
const auditLogs = [];

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

function addAuditLog({
  decision,
  reason,
  sourceService,
  targetService,
  endpoint,
  tokenId,
  statusCode,
  startedAt,
}) {
  const log = {
    eventId: randomUUID(),
    timestamp: new Date().toISOString(),
    decision,
    reason,
    sourceService: sourceService || "unknown",
    targetService: targetService || "unknown",
    endpoint: endpoint || "unknown",
    tokenId: tokenId || null,
    statusCode,
    verificationLatencyMs: Number(
      (performance.now() - startedAt).toFixed(3)
    ),
  };

  auditLogs.unshift(log);

  // Prevent unlimited memory usage
  if (auditLogs.length > 500) {
    auditLogs.pop();
  }

  console.log(
    `[${log.decision}] ${log.sourceService} -> ` +
      `${log.targetService}${log.endpoint} | ${log.reason}`
  );

  return log;
}

function sendDecision(
  res,
  statusCode,
  {
    success,
    decision,
    reason,
    sourceService,
    targetService,
    endpoint,
    tokenId,
    startedAt,
    extra = {},
  }
) {
  const audit = addAuditLog({
    decision,
    reason,
    sourceService,
    targetService,
    endpoint,
    tokenId,
    statusCode,
    startedAt,
  });

  return res.status(statusCode).json({
    success,
    decision,
    reason,
    auditEventId: audit.eventId,
    verificationLatencyMs: audit.verificationLatencyMs,
    ...extra,
  });
}

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "zero-trust-proxy",
    status: "healthy",
    auditLogCount: auditLogs.length,
  });
});

app.get("/audit-logs", (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 500);

  res.json({
    success: true,
    count: Math.min(auditLogs.length, limit),
    total: auditLogs.length,
    logs: auditLogs.slice(0, limit),
  });
});

app.delete("/audit-logs", (req, res) => {
  auditLogs.length = 0;

  res.json({
    success: true,
    message: "Audit logs cleared",
  });
});

app.post("/proxy/payment", async (req, res) => {
  const startedAt = performance.now();

  try {
    const signedRequest = req.body || {};

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
      return sendDecision(res, 400, {
        success: false,
        decision: "DENY",
        reason: "Signed request contains missing fields",
        sourceService,
        targetService,
        endpoint,
        startedAt,
      });
    }

    if (
      targetService !== "payment-service" ||
      endpoint !== "/payments/charge"
    ) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason: "Route policy does not allow this request",
        sourceService,
        targetService,
        endpoint,
        startedAt,
      });
    }

    if (!validateTimestamp(timestamp)) {
      return sendDecision(res, 401, {
        success: false,
        decision: "DENY",
        reason: "Request timestamp is expired or invalid",
        sourceService,
        targetService,
        endpoint,
        startedAt,
      });
    }

    if (isNonceUsed(nonce)) {
      return sendDecision(res, 409, {
        success: false,
        decision: "DENY",
        reason: "Replay attack detected: nonce already used",
        sourceService,
        targetService,
        endpoint,
        startedAt,
      });
    }

    let decodedToken;

    try {
      decodedToken = jwt.verify(accessToken, JWT_SECRET, {
        algorithms: ["HS256"],
      });
    } catch (error) {
      return sendDecision(res, 401, {
        success: false,
        decision: "DENY",
        reason: `Invalid access token: ${error.message}`,
        sourceService,
        targetService,
        endpoint,
        startedAt,
      });
    }

    if (decodedToken.serviceId !== sourceService) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason: "Token identity does not match source service",
        sourceService,
        targetService,
        endpoint,
        tokenId: decodedToken.tokenId,
        startedAt,
      });
    }

    if (decodedToken.audience !== targetService) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason: "Token audience does not match target service",
        sourceService,
        targetService,
        endpoint,
        tokenId: decodedToken.tokenId,
        startedAt,
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
      return sendDecision(res, 401, {
        success: false,
        decision: "DENY",
        reason: "Cryptographic signature verification failed",
        sourceService,
        targetService,
        endpoint,
        tokenId: decodedToken.tokenId,
        startedAt,
      });
    }

    const paymentResponse = await axios.post(
      `${PAYMENT_URL}${endpoint}`,
      body
    );

    return sendDecision(res, 200, {
      success: true,
      decision: "ALLOW",
      reason:
        "Identity, token, signature and route policy verified",
      sourceService,
      targetService,
      endpoint,
      tokenId: decodedToken.tokenId,
      startedAt,
      extra: {
        verifiedIdentity: sourceService,
        targetService,
        tokenId: decodedToken.tokenId,
        paymentResult: paymentResponse.data,
      },
    });
  } catch (error) {
    console.error(
      "Proxy error:",
      error.response?.data || error.message
    );

    return sendDecision(res, 500, {
      success: false,
      decision: "DENY",
      reason:
        error.response?.data?.message ||
        error.message ||
        "Proxy verification failed",
      sourceService: req.body?.sourceService,
      targetService: req.body?.targetService,
      endpoint: req.body?.endpoint,
      startedAt,
    });
  }
});

app.listen(PORT, () => {
  console.log(`Zero-Trust Proxy running at http://localhost:${PORT}`);
});