const axios = require("axios");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ORDER_URL = "http://localhost:3002";
const PROXY_URL = "http://localhost:4000";
const IDENTITY_URL = "http://localhost:4001";
const DATABASE_URL = "http://localhost:3004";

function loadIdentity(serviceName) {
  const file = path.join(
    __dirname,
    "..",
    "services",
    serviceName,
    "credentials",
    "identity.json"
  );

  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function createSigningMessage(request) {
  return [
    request.method,
    request.targetService,
    request.endpoint,
    request.timestamp,
    request.nonce,
    JSON.stringify(request.body || {}),
  ].join("\n");
}

function signRequest(request, privateKey) {
  return crypto
    .sign(
      null,
      Buffer.from(createSigningMessage(request)),
      privateKey
    )
    .toString("base64");
}

async function createPaymentRequest(amount = 2000) {
  const response = await axios.post(
    `${ORDER_URL}/create-payment-request`,
    {
      orderId: `ORD-SEC-${Date.now()}`,
      amount,
      currency: "INR",
    }
  );

  return response.data.request;
}

async function expectError(requestPromise) {
  try {
    await requestPromise;

    return null;
  } catch (error) {
    return error.response?.data || {
      reason: error.message,
    };
  }
}

function pass(message) {
  console.log(`PASS — ${message}`);
}

function fail(message, details) {
  console.error(`FAIL — ${message}`);
  console.error(details);
  process.exitCode = 1;
}

async function runTests() {
  console.log("\nSentinelMesh Security Test Suite\n");
await axios.delete(
  `${PROXY_URL}/tokens/revoked`
);

console.log("Previous revoked-token test data cleared\n");
  // 1. Valid request
  const validRequest = await createPaymentRequest(2000);

  const validResponse = await axios.post(
    `${PROXY_URL}/proxy/payment`,
    validRequest
  );

  if (validResponse.data.decision === "ALLOW") {
    pass("Valid payment request allowed");
  } else {
    fail("Valid request was not allowed", validResponse.data);
  }

  // 2. Replay attack
  const replayResult = await expectError(
    axios.post(
      `${PROXY_URL}/proxy/payment`,
      validRequest
    )
  );

  if (
    replayResult?.decision === "DENY" &&
    replayResult?.reason?.includes("Replay")
  ) {
    pass("Replay attack denied");
  } else {
    fail("Replay test failed", replayResult);
  }

  // 3. Payload tampering
  const tamperedRequest =
    await createPaymentRequest(2000);

  tamperedRequest.body.amount = 9000;

  const tamperResult = await expectError(
    axios.post(
      `${PROXY_URL}/proxy/payment`,
      tamperedRequest
    )
  );

  if (
    tamperResult?.decision === "DENY" &&
    tamperResult?.reason?.includes("signature")
  ) {
    pass("Tampered request denied");
  } else {
    fail("Tamper test failed", tamperResult);
  }

  // 4. Revoked token
  const revokedRequest =
    await createPaymentRequest(2000);

  await axios.post(
    `${PROXY_URL}/tokens/revoke`,
    {
      tokenId: revokedRequest.tokenId,
      reason: "Automated security test",
    }
  );

  const revokedResult = await expectError(
    axios.post(
      `${PROXY_URL}/proxy/payment`,
      revokedRequest
    )
  );

  if (
    revokedResult?.decision === "DENY" &&
    revokedResult?.reason?.includes("revoked")
  ) {
    pass("Revoked token denied");
    
  } else {
    fail("Revoked-token test failed", revokedResult);
  }
  await axios.delete(
  `${PROXY_URL}/tokens/revoked`
);

pass("Revoked-token test state cleared");
  

pass("Order Service obtained a fresh token");

  // 5. User Service -> Database lateral movement
  const userIdentity = loadIdentity("user-service");

  const userTokenResponse = await axios.post(
    `${IDENTITY_URL}/token`,
    {
      serviceId: "user-service",
      audience: "database-service",
    }
  );

  const lateralRequest = {
    sourceService: "user-service",
    targetService: "database-service",
    method: "POST",
    endpoint: "/transactions/store",
    timestamp: Date.now().toString(),
    nonce: crypto.randomUUID(),
    tokenId: userTokenResponse.data.tokenId,
    accessToken: userTokenResponse.data.token,
    body: {
      orderId: "ORD-LATERAL",
      amount: 2000,
      currency: "INR",
      paymentStatus: "COMPLETED",
    },
  };

  lateralRequest.signature = signRequest(
    lateralRequest,
    userIdentity.privateKey
  );

  const lateralResult = await expectError(
    axios.post(
      `${PROXY_URL}/proxy/database`,
      lateralRequest
    )
  );

  if (
    lateralResult?.decision === "DENY" &&
    lateralResult?.reason?.includes("Route policy")
  ) {
    pass("User-to-database lateral movement denied");
  } else {
    fail("Lateral-movement test failed", lateralResult);
  }

  // 6. High-value payment requires re-authentication
  const highValueRequest =
    await createPaymentRequest(15000);

  const highValueResult = await expectError(
    axios.post(
      `${PROXY_URL}/proxy/payment`,
      highValueRequest
    )
  );

  if (
    highValueResult?.decision !== "REAUTH_REQUIRED" ||
    !highValueResult.challengeId
  ) {
    fail(
      "High-value request did not create a challenge",
      highValueResult
    );

    return;
  }

  pass("High-value payment requires re-authentication");

  // 7. Approve challenge
  const approvalResponse = await axios.post(
    `${PROXY_URL}/challenges/${highValueResult.challengeId}/approve`
  );

  if (
    approvalResponse.data.decision === "ALLOW" &&
    approvalResponse.data.challengeStatus === "COMPLETED"
  ) {
    pass("Approved challenge completed payment");
  } else {
    fail(
      "Challenge approval failed",
      approvalResponse.data
    );
  }

  // 8. Transaction persistence
  const transactionResponse = await axios.get(
    `${DATABASE_URL}/transactions`
  );

  if (transactionResponse.data.count > 0) {
    pass(
      `Transactions persisted: ${transactionResponse.data.count}`
    );
  } else {
    fail(
      "No persisted transactions found",
      transactionResponse.data
    );
  }

  console.log("\nSecurity test suite completed.\n");
}

runTests().catch((error) => {
  console.error(
    "Security test suite crashed:",
    error.response?.data || error.message
  );

  process.exit(1);
});