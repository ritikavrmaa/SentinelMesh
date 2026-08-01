const axios = require("axios");

const ORDER_URL = "http://localhost:3002";
const PROXY_URL = "http://localhost:4000";

const INTERVAL_MS = 4000;
let eventNumber = 0;

function chooseScenario() {
  const random = Math.random();

  if (random < 0.6) return "VALID";
  if (random < 0.75) return "REPLAY";
  if (random < 0.87) return "TAMPER";
  if (random < 0.95) return "LATERAL";

  return "REVOKED";
}

async function requestFreshToken() {
  const response = await axios.post(
    `${ORDER_URL}/auth/token`
  );

  return response.data;
}

async function createSignedRequest(orderId) {
  const response = await axios.post(
    `${ORDER_URL}/create-payment-request`,
    {
      orderId,
      amount: 2000,
      currency: "INR",
    }
  );

  const signedRequest =
    response.data.signedRequest ||
    response.data.paymentRequest ||
    response.data.request ||
    response.data.data;

  if (!signedRequest?.sourceService || !signedRequest?.body) {
    console.log(
      "Available response keys:",
      Object.keys(response.data)
    );

    throw new Error(
      "Could not locate the signed request in the Order Service response"
    );
  }

  return signedRequest;
}
async function sendToProxy(request) {
  try {
    const response = await axios.post(
      `${PROXY_URL}/proxy/payment`,
      request
    );

    return response.data;
  } catch (error) {
    return (
      error.response?.data || {
        success: false,
        decision: "ERROR",
        reason: error.message,
      }
    );
  }
}

async function generateTraffic() {
  eventNumber += 1;

  const scenario = chooseScenario();
  const orderId = `LIVE-${scenario}-${Date.now()}`;

  try {
    console.log(
      `\n[Event ${eventNumber}] Scenario: ${scenario}`
    );

    const token = await requestFreshToken();
    const signedRequest = await createSignedRequest(orderId);

    let result;

    switch (scenario) {
      case "VALID":
        result = await sendToProxy(signedRequest);
        break;

      case "REPLAY":
        await sendToProxy(signedRequest);
        result = await sendToProxy(signedRequest);
        break;

      case "TAMPER":
        signedRequest.body.amount = 20000;
        result = await sendToProxy(signedRequest);
        break;

      case "LATERAL":
        signedRequest.endpoint = "/payments/admin";
        result = await sendToProxy(signedRequest);
        break;

      case "REVOKED":
        await axios.post(`${PROXY_URL}/tokens/revoke`, {
          tokenId: token.tokenId,
          reason: "Live anomaly detection revoked token",
        });

        result = await sendToProxy(signedRequest);
        break;

      default:
        throw new Error("Unknown traffic scenario");
    }

    console.log(
      `${result.decision}: ${result.reason}`
    );
  } catch (error) {
    console.error(
      "Live traffic error:",
      error.response?.data || error.message
    );
  }
}

console.log("SentinelMesh Live Traffic Generator");
console.log("-----------------------------------");
console.log(`Generating traffic every ${INTERVAL_MS / 1000} seconds.`);
console.log("Press Ctrl + C to stop.\n");

generateTraffic();

const trafficInterval = setInterval(
  generateTraffic,
  INTERVAL_MS
);

process.on("SIGINT", () => {
  clearInterval(trafficInterval);
  console.log("\nLive traffic generator stopped.");
  process.exit(0);
});