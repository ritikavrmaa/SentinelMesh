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

// In-memory security stores
const usedNonces = new Map();
const revokedTokens = new Map();
const auditLogs = [];
const publicKeyCache = new Map();

const PUBLIC_KEY_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Creates the exact message signed by the Order Service.
 */
function createSigningMessage(request) {
  return [
    request.method || "POST",
    request.targetService,
    request.endpoint,
    request.timestamp,
    request.nonce,
    JSON.stringify(request.body || {}),
  ].join("\n");
}

/**
 * Allows requests created within the last 30 seconds.
 */
function validateTimestamp(timestamp) {
  const requestTime = Number(timestamp);

  if (!Number.isFinite(requestTime)) {
    return false;
  }

  const difference = Math.abs(Date.now() - requestTime);

  return difference <= 30_000;
}

/**
 * Allows every nonce only once.
 */
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

/**
 * Gets a service public key using a five-minute cache.
 */
async function getServicePublicKey(serviceId) {
  const cached = publicKeyCache.get(serviceId);

  if (
    cached &&
    Date.now() - cached.cachedAt < PUBLIC_KEY_CACHE_TTL_MS
  ) {
    return {
      publicKey: cached.publicKey,
      cacheStatus: "HIT",
    };
  }

  const response = await axios.get(
    `${IDENTITY_URL}/services/${encodeURIComponent(
      serviceId
    )}/public-key`
  );

  const publicKey = response.data.publicKey;

  publicKeyCache.set(serviceId, {
    publicKey,
    cachedAt: Date.now(),
  });

  return {
    publicKey,
    cacheStatus: "MISS",
  };
}

/**
 * Adds an explainable audit entry.
 */
function addAuditLog({
  decision,
  reason,
  sourceService,
  targetService,
  endpoint,
  tokenId,
  statusCode,
  verificationLatencyMs,
  upstreamLatencyMs,
  totalLatencyMs,
  publicKeyCacheStatus,
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
    publicKeyCacheStatus: publicKeyCacheStatus || null,
    verificationLatencyMs: Number(
      verificationLatencyMs.toFixed(3)
    ),
    upstreamLatencyMs: Number(
      upstreamLatencyMs.toFixed(3)
    ),
    totalLatencyMs: Number(totalLatencyMs.toFixed(3)),
  };

  auditLogs.unshift(log);

  if (auditLogs.length > 500) {
    auditLogs.pop();
  }

  console.log(
    `[${log.decision}] ${log.sourceService} -> ` +
      `${log.targetService}${log.endpoint} | ` +
      `verification=${log.verificationLatencyMs}ms | ` +
      `upstream=${log.upstreamLatencyMs}ms | ` +
      `cache=${log.publicKeyCacheStatus || "N/A"} | ` +
      `${log.reason}`
  );

  return log;
}

/**
 * Records and sends an ALLOW or DENY response.
 */
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
    verificationCompletedAt,
    upstreamLatencyMs = 0,
    publicKeyCacheStatus,
    extra = {},
  }
) {
  const completedAt = performance.now();

  const verificationLatencyMs = verificationCompletedAt
    ? verificationCompletedAt - startedAt
    : completedAt - startedAt;

  const totalLatencyMs = completedAt - startedAt;

  const audit = addAuditLog({
    decision,
    reason,
    sourceService,
    targetService,
    endpoint,
    tokenId,
    statusCode,
    verificationLatencyMs,
    upstreamLatencyMs,
    totalLatencyMs,
    publicKeyCacheStatus,
  });

  return res.status(statusCode).json({
    success,
    decision,
    reason,
    auditEventId: audit.eventId,
    verificationLatencyMs: audit.verificationLatencyMs,
    upstreamLatencyMs: audit.upstreamLatencyMs,
    totalLatencyMs: audit.totalLatencyMs,
    publicKeyCacheStatus: audit.publicKeyCacheStatus,
    ...extra,
  });
}

/**
 * Proxy health.
 */
app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "zero-trust-proxy",
    status: "healthy",
    auditLogCount: auditLogs.length,
    cachedPublicKeys: publicKeyCache.size,
    revokedTokenCount: revokedTokens.size,
  });
});

/**
 * Return audit logs.
 */
app.get("/audit-logs", (req, res) => {
  const requestedLimit = Number(req.query.limit) || 50;
  const limit = Math.min(Math.max(requestedLimit, 1), 500);

  res.json({
    success: true,
    count: Math.min(auditLogs.length, limit),
    total: auditLogs.length,
    logs: auditLogs.slice(0, limit),
  });
});

/**
 * Clear audit logs.
 */
app.delete("/audit-logs", (req, res) => {
  auditLogs.length = 0;

  res.json({
    success: true,
    message: "Audit logs cleared",
  });
});

/**
 * Clear public-key cache.
 */
app.delete("/public-key-cache", (req, res) => {
  publicKeyCache.clear();

  res.json({
    success: true,
    message: "Public-key cache cleared",
  });
});

/**
 * Revoke a token.
 */
app.post("/tokens/revoke", (req, res) => {
  const { tokenId, reason } = req.body || {};

  if (!tokenId) {
    return res.status(400).json({
      success: false,
      message: "tokenId is required",
    });
  }

  revokedTokens.set(tokenId, {
    tokenId,
    reason:
      reason || "Security administrator revoked token",
    revokedAt: new Date().toISOString(),
  });

  return res.json({
    success: true,
    message: "Token revoked successfully",
    tokenId,
  });
});

/**
 * Return all revoked tokens.
 */
app.get("/tokens/revoked", (req, res) => {
  return res.json({
    success: true,
    count: revokedTokens.size,
    tokens: Array.from(revokedTokens.values()),
  });
});

/**
 * Clear the revoked-token list.
 */
app.delete("/tokens/revoked", (req, res) => {
  revokedTokens.clear();

  return res.json({
    success: true,
    message: "Revoked-token list cleared",
  });
});

/**
 * Zero-trust payment proxy.
 */
app.post("/proxy/payment", async (req, res) => {
  const startedAt = performance.now();

  try {
    const signedRequest = req.body || {};

    const {
      sourceService,
      targetService,
      method,
      endpoint,
      timestamp,
      nonce,
      accessToken,
      signature,
      body,
    } = signedRequest;

    // Required fields
    if (
      !sourceService ||
      !targetService ||
      !method ||
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

    // Method policy
    if (method !== "POST") {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason: "HTTP method is not allowed by policy",
        sourceService,
        targetService,
        endpoint,
        startedAt,
      });
    }

    // Route policy
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

    // Timestamp validation
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

    // Replay protection
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

    // JWT validation
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

    // Source identity validation
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

    // Audience validation
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

    // Revocation validation
    if (revokedTokens.has(decodedToken.tokenId)) {
      const revocation = revokedTokens.get(
        decodedToken.tokenId
      );

      return sendDecision(res, 401, {
        success: false,
        decision: "DENY",
        reason: `Token revoked: ${revocation.reason}`,
        sourceService,
        targetService,
        endpoint,
        tokenId: decodedToken.tokenId,
        startedAt,
      });
    }

    // Public key lookup
    const { publicKey, cacheStatus } =
      await getServicePublicKey(sourceService);

    // Ed25519 signature validation
    const signingMessage =
      createSigningMessage(signedRequest);

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
        reason:
          "Cryptographic signature verification failed",
        sourceService,
        targetService,
        endpoint,
        tokenId: decodedToken.tokenId,
        startedAt,
        publicKeyCacheStatus: cacheStatus,
      });
    }

    const verificationCompletedAt = performance.now();

    // Forward verified request
    const upstreamStartedAt = performance.now();

    const paymentResponse = await axios.post(
      `${PAYMENT_URL}${endpoint}`,
      body
    );

    const upstreamLatencyMs =
      performance.now() - upstreamStartedAt;

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
      verificationCompletedAt,
      upstreamLatencyMs,
      publicKeyCacheStatus: cacheStatus,
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
  console.log(
    `Zero-Trust Proxy running at http://localhost:${PORT}`
  );
});