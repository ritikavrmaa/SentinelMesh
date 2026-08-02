const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
const PORT = 3001;

const IDENTITY_SERVICE_URL =
  process.env.IDENTITY_SERVICE_URL ||
  "http://localhost:4001";

const ZERO_TRUST_PROXY_URL =
  process.env.ZERO_TRUST_PROXY_URL ||
  "http://localhost:4000";



const credentialsPath = path.join(
  __dirname,
  "credentials",
  "identity.json"
);

if (!fs.existsSync(credentialsPath)) {
  console.error(
    "User Service credentials were not found."
  );
  console.error(`Expected file: ${credentialsPath}`);
  process.exit(1);
}

const identity = JSON.parse(
  fs.readFileSync(credentialsPath, "utf8")
);

const SERVICE_ID = identity.serviceId;
const PRIVATE_KEY = identity.privateKey;

let orderAccessToken = null;
let orderAccessTokenId = null;

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

async function requestOrderAccessToken() {
  const response = await axios.post(
    `${IDENTITY_SERVICE_URL}/token`,
    {
      serviceId: SERVICE_ID,
      audience: "order-service",
    },
    {
      timeout: 5000,
    }
  );

  orderAccessToken = response.data.token;
  orderAccessTokenId =
    response.data.tokenId;

  return response.data;
}

async function createSignedOrderRequest({
  userId,
  item,
  quantity,
  amount,
}) {
  if (!orderAccessToken) {
    await requestOrderAccessToken();
  }

  const timestamp = Date.now().toString();
  const nonce = crypto.randomUUID();

  const orderBody = {
    userId,
    item,
    quantity,
    amount,
    currency: "INR",
  };

  const requestData = {
    method: "POST",
    targetService: "order-service",
    endpoint: "/orders/create",
    timestamp,
    nonce,
    body: orderBody,
  };

  const signature = signRequest(requestData);

  return {
    sourceService: SERVICE_ID,
    targetService: "order-service",
    method: "POST",
    endpoint: "/orders/create",
    timestamp,
    nonce,
    tokenId: orderAccessTokenId,
    accessToken: orderAccessToken,
    signature,
    body: orderBody,
  };
}

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: SERVICE_ID,
    status: "healthy",
    hasOrderAccessToken:
      Boolean(orderAccessToken),
  });
});

app.post("/place-order", async (req, res) => {
  try {
    const {
      userId,
      item,
      quantity,
      amount,
    } = req.body || {};

    if (
      !userId ||
      !item ||
      !Number.isFinite(Number(quantity)) ||
      Number(quantity) <= 0 ||
      !Number.isFinite(Number(amount)) ||
      Number(amount) <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "userId, item, positive quantity and amount are required",
      });
    }

    const signedRequest =
      await createSignedOrderRequest({
        userId,
        item,
        quantity: Number(quantity),
        amount: Number(amount),
      });

    const proxyResponse = await axios.post(
      `${ZERO_TRUST_PROXY_URL}/proxy/order`,
      signedRequest,
      {
        timeout: 10000,
      }
    );

    return res.json({
      success: true,
      message:
        "Order submitted through Zero-Trust Proxy",
      result: proxyResponse.data,
    });
  } catch (error) {
    console.error(
      "Order placement failed:",
      error.response?.data || error.message
    );

    if (error.response?.status === 401) {
      orderAccessToken = null;
      orderAccessTokenId = null;
    }

    return res.status(
      error.response?.status || 500
    ).json({
      success: false,
      message: "Order placement failed",
      details:
        error.response?.data || error.message,
    });
  }
});

app.listen(PORT, () => {
  console.log(
    `User Service running at http://localhost:${PORT}`
  );
  console.log(`Service identity: ${SERVICE_ID}`);
});