const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3003;

const IDENTITY_SERVICE_URL =
  process.env.IDENTITY_SERVICE_URL ||
  "http://localhost:4001";

const ZERO_TRUST_PROXY_URL =
  process.env.ZERO_TRUST_PROXY_URL ||
  "http://localhost:4000";

app.use(cors());
app.use(express.json());

const credentialsPath = path.join(
  __dirname,
  "credentials",
  "identity.json"
);

if (!fs.existsSync(credentialsPath)) {
  console.error(
    "Payment Service credentials were not found."
  );
  console.error(`Expected file: ${credentialsPath}`);
  process.exit(1);
}

const identity = JSON.parse(
  fs.readFileSync(credentialsPath, "utf8")
);

const SERVICE_ID = identity.serviceId;
const PRIVATE_KEY = identity.privateKey;

function createSigningMessage({
  method,
  targetService,
  endpoint,
  timestamp,
  nonce,
  body,
}) {
  return [
    String(method || "POST").toUpperCase(),
    targetService,
    endpoint,
    timestamp,
    nonce,
    JSON.stringify(body || {}),
  ].join("\n");
}

function signRequest(requestData) {
  const message =
    createSigningMessage(requestData);

  return crypto
    .sign(
      null,
      Buffer.from(message),
      PRIVATE_KEY
    )
    .toString("base64");
}

async function requestFreshDatabaseAccessToken() {
  const response = await axios.post(
    `${IDENTITY_SERVICE_URL}/token`,
    {
      serviceId: SERVICE_ID,
      audience: "database-service",
    },
    {
      timeout: 5000,
    }
  );

  return {
    accessToken: response.data.token,
    tokenId: response.data.tokenId,
    audience: response.data.audience,
    expiresIn: response.data.expiresIn,
  };
}

async function createDatabaseRequest(payment) {
  const databaseToken =
    await requestFreshDatabaseAccessToken();

  const timestamp = Date.now().toString();
  const nonce = crypto.randomUUID();

  const transactionBody = {
    orderId: payment.orderId,
    amount: payment.amount,
    currency: payment.currency,
    paymentId: payment.paymentId,
    paymentStatus: payment.status,
  };

  const requestData = {
    method: "POST",
    targetService: "database-service",
    endpoint: "/transactions/store",
    timestamp,
    nonce,
    body: transactionBody,
  };

  const signature = signRequest(requestData);

  return {
    sourceService: SERVICE_ID,
    targetService: "database-service",
    method: "POST",
    endpoint: "/transactions/store",
    body: transactionBody,
    timestamp,
    nonce,
    tokenId: databaseToken.tokenId,
    accessToken: databaseToken.accessToken,
    signature,
  };
}

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: SERVICE_ID,
    status: "healthy",
    databaseTokenStrategy:
      "fresh-token-per-request",
  });
});

app.post(
  "/auth/database-token",
  async (req, res) => {
    try {
      const tokenData =
        await requestFreshDatabaseAccessToken();

      return res.json({
        success: true,
        serviceId: SERVICE_ID,
        audience: tokenData.audience,
        tokenId: tokenData.tokenId,
        expiresIn: tokenData.expiresIn,
      });
    } catch (error) {
      console.error(
        "Database token request failed:",
        error.response?.data || error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to obtain database access token",
        details:
          error.response?.data || error.message,
      });
    }
  }
);

app.post(
  "/payments/charge",
  async (req, res) => {
    try {
      const {
        orderId,
        amount,
        currency = "INR",
      } = req.body || {};

      if (
        !orderId ||
        typeof amount !== "number" ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "orderId and a positive numeric amount are required",
        });
      }

      const payment = {
        paymentId: `PAY-${Date.now()}`,
        orderId,
        amount,
        currency,
        status: "COMPLETED",
        processedBy: SERVICE_ID,
        processedAt:
          new Date().toISOString(),
      };

      const signedDatabaseRequest =
        await createDatabaseRequest(payment);

      const databaseResponse =
        await axios.post(
          `${ZERO_TRUST_PROXY_URL}/proxy/database`,
          signedDatabaseRequest,
          {
            timeout: 5000,
          }
        );

      return res.json({
        success: true,
        message:
          "Payment processed and transaction stored securely",
        payment,
        databaseStorage: {
          decision:
            databaseResponse.data.decision,
          auditEventId:
            databaseResponse.data.auditEventId,
          policyTier:
            databaseResponse.data.policyTier,
          result:
            databaseResponse.data.databaseResult,
        },
      });
    } catch (error) {
      console.error(
        "Payment processing failed:",
        error.response?.data || error.message
      );

      return res.status(
        error.response?.status || 500
      ).json({
        success: false,
        message:
          "Payment or secure transaction storage failed",
        details:
          error.response?.data || error.message,
      });
    }
  }
);

app.listen(PORT, () => {
  console.log(
    `Payment Service running at http://localhost:${PORT}`
  );
  console.log(`Service identity: ${SERVICE_ID}`);
  console.log(
    "Database token strategy: fresh token per request"
  );
});