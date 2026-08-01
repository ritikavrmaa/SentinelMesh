const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const IDENTITY_URL = "http://localhost:4001";
const PROXY_URL = "http://localhost:4000";

const credentialsPath = path.join(
  __dirname,
  "..",
  "services",
  "user-service",
  "credentials",
  "identity.json"
);

if (!fs.existsSync(credentialsPath)) {
  console.error("User Service credentials not found.");
  process.exit(1);
}

const identity = JSON.parse(
  fs.readFileSync(credentialsPath, "utf8")
);

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

async function testLateralMovement() {
  try {
    const tokenResponse = await axios.post(
      `${IDENTITY_URL}/token`,
      {
        serviceId: identity.serviceId,
        audience: "database-service",
      }
    );

    const request = {
      sourceService: "user-service",
      targetService: "database-service",
      method: "POST",
      endpoint: "/transactions/store",
      timestamp: Date.now().toString(),
      nonce: crypto.randomUUID(),
      accessToken: tokenResponse.data.token,
      tokenId: tokenResponse.data.tokenId,
      body: {
        orderId: "ORD-LATERAL-TEST",
        amount: 2000,
        currency: "INR",
        paymentStatus: "COMPLETED",
      },
    };

    request.signature = crypto
      .sign(
        null,
        Buffer.from(createSigningMessage(request)),
        identity.privateKey
      )
      .toString("base64");

    await axios.post(
      `${PROXY_URL}/proxy/database`,
      request
    );

    console.log(
      "FAILED: Unauthorized lateral movement was allowed"
    );
    process.exitCode = 1;
  } catch (error) {
    const result = error.response?.data;

    if (
      result?.decision === "DENY" &&
      result?.reason ===
        "Route policy does not allow this request"
    ) {
      console.log(
        "PASS: User Service → Database Service was denied"
      );
      console.log(`Reason: ${result.reason}`);
      return;
    }

    console.error(
      "Unexpected test result:",
      result || error.message
    );

    process.exitCode = 1;
  }
}

testLateralMovement();