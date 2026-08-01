const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3002;

app.use(cors());
app.use(express.json());

const credentialsPath = path.join(
  __dirname,
  "credentials",
  "identity.json"
);

if (!fs.existsSync(credentialsPath)) {
  console.error("Order Service credentials were not found.");
  console.error(`Expected file: ${credentialsPath}`);
  process.exit(1);
}

const identity = JSON.parse(
  fs.readFileSync(credentialsPath, "utf8")
);

const SERVICE_ID = identity.serviceId;
const PRIVATE_KEY = identity.privateKey;
const IDENTITY_SERVICE_URL = "http://localhost:4001";

let accessToken = null;
let accessTokenId = null;

/**
 * Creates the same string that the proxy will later verify.
 */
function createSigningMessage({
  method,
  targetService,
  endpoint,
  timestamp,
  nonce,
  body,
}) {
  const canonicalBody = JSON.stringify(body || {});

  return [
    method.toUpperCase(),
    targetService,
    endpoint,
    timestamp,
    nonce,
    canonicalBody,
  ].join("\n");
}

/**
 * Signs a request using the Order Service private key.
 */
function signRequest(requestData) {
  const message = createSigningMessage(requestData);

  return crypto.sign(
    null,
    Buffer.from(message),
    PRIVATE_KEY
  ).toString("base64");
}

/**
 * Gets a short-lived token for calling Payment Service.
 */
async function requestAccessToken() {
  const response = await axios.post(
    `${IDENTITY_SERVICE_URL}/token`,
    {
      serviceId: SERVICE_ID,
      audience: "payment-service",
    }
  );

  accessToken = response.data.token;
  accessTokenId = response.data.tokenId;

  return response.data;
}

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: SERVICE_ID,
    status: "healthy",
    hasAccessToken: Boolean(accessToken),
  });
});

/**
 * Requests a JWT from the Identity Service.
 */
app.post("/auth/token", async (req, res) => {
  try {
    const tokenData = await requestAccessToken();

    res.json({
      success: true,
      serviceId: SERVICE_ID,
      audience: tokenData.audience,
      tokenId: tokenData.tokenId,
      expiresIn: tokenData.expiresIn,
    });
  } catch (error) {
    console.error(
      "Token request failed:",
      error.response?.data || error.message
    );

    res.status(500).json({
      success: false,
      error: "Unable to obtain service token",
      details: error.response?.data || error.message,
    });
  }
});

/**
 * Creates a signed payment request.
 * Later, this request will go through the Zero-Trust Proxy.
 */
app.post("/create-payment-request", async (req, res) => {
  try {
   const { orderId, amount, currency } = req.body;

    if (!orderId || typeof amount !== "number" || amount <= 0) {
      return res.status(400).json({
        success: false,
        error: "Valid orderId and positive numeric amount are required",
      });
    }

    if (!accessToken) {
      await requestAccessToken();
    }

    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();

   const paymentBody = {
  orderId,
  amount,
  currency: "INR",
};

    const requestData = {
      method: "POST",
      targetService: "payment-service",
      endpoint: "/payments/charge",
      timestamp,
      nonce,
      body: paymentBody,
    };

    const signature = signRequest(requestData);

    res.json({
      success: true,
      message: "Signed payment request created",
      request: {
        sourceService: SERVICE_ID,
        targetService: "payment-service",
        method: "POST",
        endpoint: "/payments/charge",
        body: paymentBody,
        timestamp,
        nonce,
        tokenId: accessTokenId,
        accessToken,
        signature,
      },
    });
  } catch (error) {
    console.error(
      "Payment request creation failed:",
      error.response?.data || error.message
    );

    res.status(500).json({
      success: false,
      error: "Unable to create signed payment request",
      details: error.response?.data || error.message,
    });
  }
});

app.listen(PORT, () => {
  console.log(`Order Service running at http://localhost:${PORT}`);
});