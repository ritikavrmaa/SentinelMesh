const axios = require("axios");

const ORDER_SERVICE_URL = "http://localhost:3002";
const PROXY_URL = "http://localhost:4000";

async function testReplayAttack() {
  try {
    console.log("\n1. Requesting a fresh access token...");

    const tokenResponse = await axios.post(
      `${ORDER_SERVICE_URL}/auth/token`
    );

    console.log(
      `Fresh token received: ${tokenResponse.data.tokenId}`
    );

    console.log("\n2. Creating one signed payment request...");

    const signedResponse = await axios.post(
      `${ORDER_SERVICE_URL}/create-payment-request`,
      {
        orderId: "ORD-REPLAY-001",
        amount: 2000,
      }
    );

    const signedRequest = signedResponse.data.request;

    console.log(`Nonce: ${signedRequest.nonce}`);

    console.log("\n3. Sending request for the first time...");

    const firstResponse = await axios.post(
      `${PROXY_URL}/proxy/payment`,
      signedRequest
    );

    console.log("FIRST REQUEST RESULT:");
    console.log(
      JSON.stringify(firstResponse.data, null, 2)
    );

    console.log(
      "\n4. Sending the exact same signed request again..."
    );

    try {
      await axios.post(
        `${PROXY_URL}/proxy/payment`,
        signedRequest
      );
    } catch (error) {
      console.log("SECOND REQUEST RESULT:");
      console.log(
        JSON.stringify(
          error.response?.data || {
            success: false,
            message: error.message,
          },
          null,
          2
        )
      );
    }

    console.log(
      "\nReplay attack test completed successfully."
    );
  } catch (error) {
    console.error(
      "\nReplay test failed:",
      error.response?.data || error.message
    );
  }
}

testReplayAttack();