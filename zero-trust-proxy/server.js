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
const DATABASE_URL = "http://localhost:3004";
const ORDER_URL = "http://localhost:3002";

const POLICY_FILE = path.join(
  __dirname,
  "..",
  "policies",
  "access-policies.json"
);
const DATA_DIRECTORY = path.join(
  __dirname,
  "data"
);

const AUDIT_LOGS_FILE = path.join(
  DATA_DIRECTORY,
  "audit-logs.json"
);

const REVOKED_TOKENS_FILE = path.join(
  DATA_DIRECTORY,
  "revoked-tokens.json"
);

const CHALLENGES_FILE = path.join(
  DATA_DIRECTORY,
  "reauth-challenges.json"
);

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "sentinelmesh-development-secret-change-later";

const PUBLIC_KEY_CACHE_TTL_MS = 5 * 60 * 1000;

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const usedNonces = new Map();
const revokedTokens = new Map();
const auditLogs = [];
const publicKeyCache = new Map();
const reauthChallenges = new Map();
function ensureDataStorage() {
  if (!fs.existsSync(DATA_DIRECTORY)) {
    fs.mkdirSync(DATA_DIRECTORY, {
      recursive: true,
    });
  }

  const files = [
    AUDIT_LOGS_FILE,
    REVOKED_TOKENS_FILE,
    CHALLENGES_FILE,
  ];

  for (const file of files) {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(
        file,
        JSON.stringify([], null, 2)
      );
    }
  }
}

function readJsonFile(file) {
  try {
    ensureDataStorage();

    const raw = fs.readFileSync(file, "utf8");

    return raw ? JSON.parse(raw) : [];
  } catch (error) {
    console.error(
      `Unable to read ${file}:`,
      error.message
    );

    return [];
  }
}

function writeJsonFile(file, data) {
  try {
    ensureDataStorage();

    const temporaryFile = `${file}.tmp`;

    fs.writeFileSync(
      temporaryFile,
      JSON.stringify(data, null, 2)
    );

    fs.renameSync(temporaryFile, file);
  } catch (error) {
    console.error(
      `Unable to write ${file}:`,
      error.message
    );
  }
}

function saveAuditLogs() {
  writeJsonFile(
    AUDIT_LOGS_FILE,
    auditLogs
  );
}

function saveRevokedTokens() {
  writeJsonFile(
    REVOKED_TOKENS_FILE,
    Array.from(revokedTokens.values())
  );
}

function saveChallenges() {
  writeJsonFile(
    CHALLENGES_FILE,
    Array.from(reauthChallenges.values())
  );
}

function loadPersistentState() {
  const storedAuditLogs =
    readJsonFile(AUDIT_LOGS_FILE);

  const storedRevokedTokens =
    readJsonFile(REVOKED_TOKENS_FILE);

  const storedChallenges =
    readJsonFile(CHALLENGES_FILE);

  auditLogs.length = 0;
  saveAuditLogs();
  auditLogs.push(...storedAuditLogs);

  revokedTokens.clear();

  for (const token of storedRevokedTokens) {
    if (token.tokenId) {
      revokedTokens.set(
        token.tokenId,
        token
      );
    }
  }

  reauthChallenges.clear();

  for (const challenge of storedChallenges) {
    if (challenge.challengeId) {
      reauthChallenges.set(
        challenge.challengeId,
        challenge
      );
    }
  }

  console.log(
    `Loaded persistent state: ` +
      `${auditLogs.length} audits, ` +
      `${revokedTokens.size} revoked tokens, ` +
      `${reauthChallenges.size} challenges`
  );
}

function loadPolicies() {
  try {
    const raw = fs.readFileSync(POLICY_FILE, "utf8");
    const parsed = JSON.parse(raw);

    if (!Array.isArray(parsed.routes)) {
      throw new Error(
        "Policy file must contain a routes array"
      );
    }

    return parsed.routes;
  } catch (error) {
    console.error(
      "Unable to load policies:",
      error.message
    );

    return [];
  }
}

function findMatchingPolicy({
  sourceService,
  targetService,
  method,
  endpoint,
}) {
  return loadPolicies().find(
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
      reason: "No additional constraints",
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
      String(body.orderId).trim() === "")
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

function createReauthChallenge({
  sourceService,
  targetService,
  endpoint,
  tokenId,
  body,
}) {
  const challengeId = randomUUID();

  const challenge = {
    challengeId,
    sourceService,
    targetService,
    endpoint,
    tokenId,
    requestBody: body,
    status: "PENDING",
    createdAt: new Date().toISOString(),
    expiresAt: new Date(
      Date.now() + 5 * 60 * 1000
    ).toISOString(),
  };

  reauthChallenges.set(challengeId, challenge);

  return challenge;
}

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

function validateTimestamp(timestamp) {
  const requestTime = Number(timestamp);

  if (!Number.isFinite(requestTime)) {
    return false;
  }

  return Math.abs(Date.now() - requestTime) <= 30_000;
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

function addAuditLog({
  decision,
  reason,
  sourceService,
  targetService,
  endpoint,
  tokenId,
  statusCode,
  verificationLatencyMs = 0,
  upstreamLatencyMs = 0,
  totalLatencyMs = 0,
  publicKeyCacheStatus,
  policyTier,
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
    policyTier: policyTier || null,
    publicKeyCacheStatus:
      publicKeyCacheStatus || null,
    verificationLatencyMs: Number(
      Number(verificationLatencyMs || 0).toFixed(3)
    ),
    upstreamLatencyMs: Number(
      Number(upstreamLatencyMs || 0).toFixed(3)
    ),
    totalLatencyMs: Number(
      Number(totalLatencyMs || 0).toFixed(3)
    ),
  };

  auditLogs.unshift(log);

  if (auditLogs.length > 500) {
    auditLogs.pop();
  }
  saveAuditLogs();

  console.log(
    `[${log.decision}] ${log.sourceService} -> ` +
      `${log.targetService}${log.endpoint} | ` +
      `tier=${log.policyTier || "N/A"} | ` +
      `verification=${log.verificationLatencyMs}ms | ` +
      `upstream=${log.upstreamLatencyMs}ms | ` +
      `cache=${log.publicKeyCacheStatus || "N/A"} | ` +
      log.reason
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

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "zero-trust-proxy",
    status: "healthy",
    persistence: "enabled",
    auditLogCount: auditLogs.length,
    cachedPublicKeys: publicKeyCache.size,
    revokedTokenCount: revokedTokens.size,
    reauthChallengeCount: reauthChallenges.size,
    loadedPolicyCount: loadPolicies().length,
  });
});

app.get("/policies", (req, res) => {
  const policies = loadPolicies();

  res.json({
    success: true,
    count: policies.length,
    policies,
  });
});

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

app.delete("/audit-logs", (req, res) => {
  auditLogs.length = 0;

  res.json({
    success: true,
    message: "Audit logs cleared",
  });
});

app.delete("/public-key-cache", (req, res) => {
  publicKeyCache.clear();

  res.json({
    success: true,
    message: "Public-key cache cleared",
  });
});

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
  saveRevokedTokens();

  return res.json({
    success: true,
    message: "Token revoked successfully",
    tokenId,
  });
});

app.get("/tokens/revoked", (req, res) => {
  res.json({
    success: true,
    count: revokedTokens.size,
    tokens: Array.from(revokedTokens.values()),
  });
});

app.delete("/tokens/revoked", (req, res) => {
  revokedTokens.clear();
  saveRevokedTokens();

  res.json({
    success: true,
    message: "Revoked-token list cleared",
  });
});

app.get("/challenges", (req, res) => {
  const challenges = Array.from(
    reauthChallenges.values()
  ).sort(
    (a, b) =>
      new Date(b.createdAt) - new Date(a.createdAt)
  );

  res.json({
    success: true,
    count: challenges.length,
    challenges,
  });
});

app.post(
  "/challenges/:challengeId/approve",
  async (req, res) => {
    const { challengeId } = req.params;

    const challenge =
      reauthChallenges.get(challengeId);

    if (!challenge) {
      return res.status(404).json({
        success: false,
        message: "Challenge not found",
      });
    }

    if (challenge.status === "COMPLETED") {
      return res.status(409).json({
        success: false,
        message:
          "Challenge has already been completed",
      });
    }

    if (
      Date.now() >
      new Date(challenge.expiresAt).getTime()
    ) {
      challenge.status = "EXPIRED";
      reauthChallenges.set(challengeId, challenge);
saveChallenges();
      return res.status(410).json({
        success: false,
        message: "Challenge has expired",
        challenge,
      });
    }

    try {
      challenge.status = "APPROVED";
      challenge.approvedAt =
        new Date().toISOString();

      reauthChallenges.set(
        challengeId,
        challenge
      );

      const upstreamStartedAt =
        performance.now();

      const paymentResponse = await axios.post(
        `${PAYMENT_URL}${challenge.endpoint}`,
        challenge.requestBody,
        {
          timeout: 5000,
        }
      );

      const upstreamLatencyMs =
        performance.now() - upstreamStartedAt;

      challenge.status = "COMPLETED";
      challenge.completedAt =
        new Date().toISOString();
      challenge.paymentResult =
        paymentResponse.data;

      reauthChallenges.set(
        challengeId,
        challenge
      );

      addAuditLog({
        decision: "ALLOW",
        reason:
          "High-value payment allowed after successful re-authentication",
        sourceService:
          challenge.sourceService,
        targetService:
          challenge.targetService,
        endpoint: challenge.endpoint,
        tokenId: challenge.tokenId,
        statusCode: 200,
        verificationLatencyMs: 0,
        upstreamLatencyMs,
        totalLatencyMs: upstreamLatencyMs,
        publicKeyCacheStatus: null,
        policyTier: "intent-bound",
      });

      return res.json({
        success: true,
        decision: "ALLOW",
        message:
          "Re-authentication approved and payment completed",
        challengeId,
        challengeStatus: challenge.status,
        paymentResult: paymentResponse.data,
        upstreamLatencyMs: Number(
          upstreamLatencyMs.toFixed(3)
        ),
      });
    } catch (error) {
      challenge.status = "FAILED";
      challenge.failureReason =
        error.response?.data?.message ||
        error.message;

      reauthChallenges.set(
        challengeId,
        challenge
      );

      return res.status(500).json({
        success: false,
        decision: "DENY",
        message:
          "Payment failed after challenge approval",
        error: challenge.failureReason,
      });
    }
  }
);
app.post("/proxy/database", async (req, res) => {
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
        policyTier: matchedPolicy.tier,
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
        policyTier: matchedPolicy.tier,
      });
    }

    let decodedToken;

    try {
      decodedToken = jwt.verify(accessToken, JWT_SECRET, {
        algorithms: ["HS256"],
      });

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

    if (decodedToken.serviceId !== sourceService) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason: "Token identity does not match source service",
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        policyTier: matchedPolicy.tier,
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
        tokenId,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

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

    const publicKeyResult =
      await getServicePublicKey(sourceService);

    const publicKey = publicKeyResult.publicKey;
    cacheStatus = publicKeyResult.cacheStatus;

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
        reason: "Cryptographic signature verification failed",
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        publicKeyCacheStatus: cacheStatus,
        policyTier: matchedPolicy.tier,
      });
    }

    if (
      targetService !== "database-service" ||
      endpoint !== "/transactions/store"
    ) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason: "Database proxy target is not allowed",
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        publicKeyCacheStatus: cacheStatus,
        policyTier: matchedPolicy.tier,
      });
    }

    const verificationCompletedAt =
      performance.now();

    const upstreamStartedAt =
      performance.now();

    const databaseResponse = await axios.post(
      `${DATABASE_URL}${endpoint}`,
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
        "Identity, token, signature and database route policy verified",
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
        databaseResult: databaseResponse.data,
      },
    });
  } catch (error) {
    console.error(
      "Database proxy error:",
      error.response?.data || error.message
    );

    return sendDecision(res, 500, {
      success: false,
      decision: "DENY",
      reason:
        error.response?.data?.message ||
        error.message ||
        "Database proxy verification failed",
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
app.post("/proxy/order", async (req, res) => {
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
        policyTier: matchedPolicy.tier,
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
        policyTier: matchedPolicy.tier,
      });
    }

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

    if (decodedToken.serviceId !== sourceService) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason: "Token identity does not match source service",
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        policyTier: matchedPolicy.tier,
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
        tokenId,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

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

    const publicKeyResult =
      await getServicePublicKey(sourceService);

    const publicKey = publicKeyResult.publicKey;
    cacheStatus = publicKeyResult.cacheStatus;

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

    if (
      targetService !== "order-service" ||
      endpoint !== "/orders/create"
    ) {
      return sendDecision(res, 403, {
        success: false,
        decision: "DENY",
        reason: "Order proxy target is not allowed",
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        publicKeyCacheStatus: cacheStatus,
        policyTier: matchedPolicy.tier,
      });
    }

    const verificationCompletedAt =
      performance.now();

    const upstreamStartedAt =
      performance.now();

    const orderResponse = await axios.post(
      `${ORDER_URL}${endpoint}`,
      body,
      {
        timeout: 5000,
      }
    );

    const upstreamLatencyMs =
      performance.now() - upstreamStartedAt;

    return sendDecision(res, 201, {
      success: true,
      decision: "ALLOW",
      reason:
        "Identity, token, signature and order route policy verified",
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
        orderResult: orderResponse.data,
      },
    });
  } catch (error) {
    console.error(
      "Order proxy error:",
      error.response?.data || error.message
    );

    return sendDecision(res, 500, {
      success: false,
      decision: "DENY",
      reason:
        error.response?.data?.message ||
        error.message ||
        "Order proxy verification failed",
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
        reason:
          `Invalid access token: ${error.message}`,
        sourceService,
        targetService,
        endpoint,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

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

    if (revokedTokens.has(tokenId)) {
      const revocation = revokedTokens.get(tokenId);

      return sendDecision(res, 401, {
        success: false,
        decision: "DENY",
        reason:
          `Token revoked: ${revocation.reason}`,
        sourceService,
        targetService,
        endpoint,
        tokenId,
        startedAt,
        policyTier: matchedPolicy.tier,
      });
    }

    const publicKeyResult =
      await getServicePublicKey(sourceService);

    const publicKey = publicKeyResult.publicKey;
    cacheStatus = publicKeyResult.cacheStatus;

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

    const policyEvaluation =
      evaluatePolicyConstraints(
        matchedPolicy,
        body
      );

    if (!policyEvaluation.allowed) {
      let challenge = null;

      if (
        policyEvaluation.decision ===
        "REAUTH_REQUIRED"
      ) {
        challenge = createReauthChallenge({
          sourceService,
          targetService,
          endpoint,
          tokenId,
          body,
        });
      }

      return sendDecision(
        res,
        policyEvaluation.statusCode,
        {
          success: false,
          decision:
            policyEvaluation.decision,
          reason: policyEvaluation.reason,
          sourceService,
          targetService,
          endpoint,
          tokenId,
          startedAt,
          publicKeyCacheStatus: cacheStatus,
          policyTier: matchedPolicy.tier,
          extra: {
            challengeId:
              challenge?.challengeId || null,
            challengeStatus:
              challenge?.status || null,
            challengeExpiresAt:
              challenge?.expiresAt || null,
            constraints:
              matchedPolicy.constraints,
            requestContext: {
              orderId: body.orderId || null,
              amount: body.amount || null,
              currency:
                body.currency || null,
            },
          },
        }
      );
    }

    const verificationCompletedAt =
      performance.now();

    if (
      targetService !== "payment-service" ||
      endpoint !== "/payments/charge"
    ) {
      return sendDecision(res, 501, {
        success: false,
        decision: "DENY",
        reason:
          "Policy is valid, but no upstream adapter exists for this target",
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

    const upstreamStartedAt =
      performance.now();

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
loadPersistentState();
app.listen(PORT, () => {
  console.log(
    `Zero-Trust Proxy running at http://localhost:${PORT}`
  );
  console.log(`Policy file: ${POLICY_FILE}`);
  console.log(
    `Loaded policies: ${loadPolicies().length}`
  );
});