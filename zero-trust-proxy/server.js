const fs = require("fs");
const path = require("path");

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { randomUUID } = require("crypto");

const app = express();

const PORT = 4000;
const IDENTITY_URL = "http://localhost:4001";
const PAYMENT_URL = "http://localhost:3003";

const POLICY_FILE = path.join(
  __dirname,
  "..",
  "policies",
  "access-policies.json"
);

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "sentinelmesh-development-secret-change-later";

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// In-memory security stores
const usedNonces = new Map();
const revokedTokens = new Map();
const auditLogs = [];
const publicKeyCache = new Map();

const PUBLIC_KEY_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Loads the latest access policies from the JSON file.
 *
 * The file is read for every request so policy changes can
 * take effect without restarting the proxy.
 */
function loadPolicies() {
  try {
    const rawPolicies = fs.readFileSync(POLICY_FILE, "utf8");
    const parsedPolicies = JSON.parse(rawPolicies);

    if (!Array.isArray(parsedPolicies.routes)) {
      throw new Error(
        "Policy file must contain a routes array"
      );
    }

    return parsedPolicies.routes;
  } catch (error) {
    console.error(
      "Unable to load access policies:",
      error.message
    );

    return [];
  }
}

/**
 * Finds the policy matching the request's source, target,
 * HTTP method and endpoint.
 */
function findMatchingPolicy({
  sourceService,
  targetService,
  method,
  endpoint,
}) {
  const policies = loadPolicies();

  return policies.find(
    (policy) =>
      policy.source === sourceService &&
      policy.target === targetService &&
      String(policy.method || "").toUpperCase() ===
        String(method || "").toUpperCase() &&
      policy.endpoint === endpoint
  );
}
function evaluatePolicyConstraints(policy, body) {
  if (!policy.constraints) {
    return {
      allowed: true,
      decision: "ALLOW",
      reason: "No additional policy constraints",
    };
  }

  const {
    maxAmount,
    requireOrderId,
    allowedCurrency,
  } = policy.constraints;

  if (
    requireOrderId &&
    (!body.orderId ||
      String(body.orderId).trim().length === 0)
  ) {
    return {
      allowed: false,
      decision: "DENY",
      statusCode: 403,
      reason:
        "Intent policy denied request: orderId is required",
    };
  }

  if (
    allowedCurrency &&
    body.currency !== allowedCurrency
  ) {
    return {
      allowed: false,
      decision: "DENY",
      statusCode: 403,
      reason:
        `Intent policy denied request: currency must be ${allowedCurrency}`,
    };
  }

  const amount = Number(body.amount);

  if (!Number.isFinite(amount) || amount <= 0) {
    return {
      allowed: false,
      decision: "DENY",
      statusCode: 400,
      reason:
        "Intent policy denied request: amount must be a positive number",
    };
  }

  if (
    Number.isFinite(Number(maxAmount)) &&
    amount > Number(maxAmount)
  ) {
    return {
      allowed: false,
      decision: "REAUTH_REQUIRED",
      statusCode: 401,
      reason:
        `Dynamic re-authentication required: amount ${amount} exceeds policy limit ${maxAmount}`,
    };
  }

  return {
    allowed: true,
    decision: "ALLOW",
    reason: "Policy constraints verified",
  };
}
/**
 * Creates the exact message signed by the source service.
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
    Date.now() - cached.cachedAt <
      PUBLIC_KEY_CACHE_TTL_MS
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
  policyTier,
}) {
  const safeVerificationLatency = Number.isFinite(
    verificationLatencyMs
  )
    ? verificationLatencyMs
    : 0;

  const safeUpstreamLatency = Number.isFinite(
    upstreamLatencyMs
  )
    ? upstreamLatencyMs
    : 0;

  const safeTotalLatency = Number.isFinite(totalLatencyMs)
    ? totalLatencyMs
    : 0;

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
    policyTier: policyTier || null,
    publicKeyCacheStatus:
      publicKeyCacheStatus || null,
    verificationLatencyMs: Number(
      safeVerificationLatency.toFixed(3)
    ),
    upstreamLatencyMs: Number(
      safeUpstreamLatency.toFixed(3)
    ),
    totalLatencyMs: Number(
      safeTotalLatency.toFixed(3)
    ),
  };

  auditLogs.unshift(log);

  if (auditLogs.length > 500) {
    auditLogs.pop();
  }

  console.log(
    `[${log.decision}] ${log.sourceService} -> ` +
      `${log.targetService}${log.endpoint} | ` +
      `tier=${log.policyTier || "N/A"} | ` +
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
    policyTier,
    extra = {},
  }
) {
  const completedAt = performance.now();

  const verificationLatencyMs =
    verificationCompletedAt !== undefined
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
    policyTier,
  });

  return res.status(statusCode).json({
    success,
    decision,
    reason,
    auditEventId: audit.eventId,
    policyTier: audit.policyTier,
    verificationLatencyMs:
      audit.verificationLatencyMs,
    upstreamLatencyMs: audit.upstreamLatencyMs,
    totalLatencyMs: audit.totalLatencyMs,
    publicKeyCacheStatus:
      audit.publicKeyCacheStatus,
    ...extra,
  });
}

/**
 * Proxy health.
 */
app.get("/health", (req, res) => {
  const policies = loadPolicies();

  res.json({
    success: true,
    service: "zero-trust-proxy",
    status: "healthy",
    auditLogCount: auditLogs.length,
    cachedPublicKeys: publicKeyCache.size,
    revokedTokenCount: revokedTokens.size,
    loadedPolicyCount: policies.length,
  });
});

/**
 * Return the currently loaded policies.
 */
app.get("/policies", (req, res) => {
  const policies = loadPolicies();

  return res.json({
    success: true,
    count: policies.length,
    policies,
  });
});

/**
 * Return audit logs.
 */
app.get("/audit-logs", (req, res) => {
  const requestedLimit = Number(req.query.limit) || 50;
  const limit = Math.min(
    Math.max(requestedLimit, 1),
    500
  );

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
      reason ||
      "Security administrator revoked token",
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

  let matchedPolicy;
  let sourceService;
  let targetService;
  let endpoint;
  let tokenId;
  let cacheStatus;

  try {
    const signedRequest = req.body || {};

    const {
      method,
      timestamp,
      nonce,
      accessToken,
      signature,
      body,
    } = signedRequest;

    sourceService = signedRequest.sourceService;
    targetService = signedRequest.targetService;
    endpoint = signedRequest.endpoint;

    // Required-field validation
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
        reason:
          "Signed request contains missing fields",
        sourceService,
        targetService,
        endpoint,
        startedAt,
      });
    }

    /*
     * Dynamic route-policy validation.
     *
     * This replaces the old hard-coded check for:
     * order-service -> payment-service.
     */
    matchedPolicy = findMatchingPolicy({
      sourceService,
      targetService,
      method,
      endpoint,
    });

    if (!matchedPolicy) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason:
          "Route policy does not allow this request",
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
        reason:
          "Request timestamp is expired or invalid",
        sourceService,
        targetService,
        endpoint,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

    // Replay protection
    if (isNonceUsed(nonce)) {
      return sendDecision(res, 409, {
        success: false,
        decision: "DENY",
        reason:
          "Replay attack detected: nonce already used",
        sourceService,
        targetService,
        endpoint,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

    // JWT validation
    let decodedToken;

    try {
      decodedToken = jwt.verify(
        accessToken,
        JWT_SECRET,
        {
          algorithms: ["HS256"],
        }
      );

      tokenId = decodedToken.tokenId;
    } catch (error) {
      return sendDecision(res, 401, {
        success: false,
        decision: "DENY",
        reason: `Invalid access token: ${error.message}`,
        sourceService,
        targetService,
        endpoint,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

    // Source identity validation
    if (decodedToken.serviceId !== sourceService) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason:
          "Token identity does not match source service",
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

    // Audience validation
    if (decodedToken.audience !== targetService) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason:
          "Token audience does not match target service",
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

    // Token-revocation validation
    if (revokedTokens.has(tokenId)) {
      const revocation = revokedTokens.get(tokenId);

      return sendDecision(res, 401, {
        success: false,
        decision: "DENY",
        reason: `Token revoked: ${revocation.reason}`,
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

    // Public-key lookup
    const publicKeyResult =
      await getServicePublicKey(sourceService);

    const publicKey = publicKeyResult.publicKey;
    cacheStatus = publicKeyResult.cacheStatus;

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
        tokenId,
        startedAt,
        publicKeyCacheStatus: cacheStatus,
        policyTier: matchedPolicy.tier,
      });
    }
    const policyEvaluation = evaluatePolicyConstraints(
  matchedPolicy,
  body
);

if (!policyEvaluation.allowed) {
  return sendDecision(
    res,
    policyEvaluation.statusCode,
    {
      success: false,
      decision: policyEvaluation.decision,
      reason: policyEvaluation.reason,
      sourceService,
      targetService,
      endpoint,
      tokenId,
      startedAt,
      publicKeyCacheStatus: cacheStatus,
      policyTier: matchedPolicy.tier,
      extra: {
        constraints: matchedPolicy.constraints,
        requestContext: {
          orderId: body.orderId || null,
          amount: body.amount || null,
          currency: body.currency || null,
        },
      },
    }
  );
}

    const verificationCompletedAt =
      performance.now();

    // This route currently forwards only payment requests.
    if (
      targetService !== "payment-service" ||
      endpoint !== "/payments/charge"
    ) {
      return sendDecision(res, 501, {
        success: false,
        decision: "DENY",
        reason:
          "Policy is valid, but this proxy handler does not yet have an upstream adapter for the target service",
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        verificationCompletedAt,
        publicKeyCacheStatus: cacheStatus,
        policyTier: matchedPolicy.tier,
      });
    }

    // Forward the verified request
    const upstreamStartedAt = performance.now();

    const paymentResponse = await axios.post(
      `${PAYMENT_URL}${endpoint}`,
      body,
      {
        timeout: 5000,
      }
    );

    const upstreamLatencyMs =
      performance.now() - upstreamStartedAt;

    return sendDecision(res, 200, {
      success: true,
      decision: "ALLOW",
      reason:
        "Identity, token, signature and dynamic route policy verified",
      sourceService,
      targetService,
      endpoint,
      tokenId,
      startedAt,
      verificationCompletedAt,
      upstreamLatencyMs,
      publicKeyCacheStatus: cacheStatus,
      policyTier: matchedPolicy.tier,
      extra: {
        verifiedIdentity: sourceService,
        targetService,
        tokenId,
        matchedPolicy: {
          source: matchedPolicy.source,
          target: matchedPolicy.target,
          method: matchedPolicy.method,
          endpoint: matchedPolicy.endpoint,
          tier: matchedPolicy.tier,
        },
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
      sourceService,
      targetService,
      endpoint,
      tokenId,
      startedAt,
      publicKeyCacheStatus: cacheStatus,
      policyTier: matchedPolicy?.tier,
    });
  }
});

app.listen(PORT, () => {
  console.log(
    `Zero-Trust Proxy running at http://localhost:${PORT}`
  );
  console.log(`Policy file: ${POLICY_FILE}`);
  console.log(
    `Loaded policies: ${loadPolicies().length}`
  );
});