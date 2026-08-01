const axios = require("axios");

const ORDER_SERVICE_URL = "http://localhost:3002";
const PROXY_URL = "http://localhost:4000";

async function testLateralMovement() {
  try {
    console.log("\n1. Requesting a fresh access token...");

    const tokenResponse = await axios.post(
      `${ORDER_SERVICE_URL}/auth/token`
    );

    console.log(
      `Fresh token received: ${tokenResponse.data.tokenId}`
    );

    console.log("\n2. Creating a valid signed payment request...");

    const signedResponse = await axios.post(
      `${ORDER_SERVICE_URL}/create-payment-request`,
      {
        orderId: "ORD-LATERAL-001",
        amount: 2000,
      }
    );

    const signedRequest = signedResponse.data.request;

    console.log(`Original endpoint: ${signedRequest.endpoint}`);

    console.log(
      "\n3. Simulating lateral movement to an unauthorized endpoint..."
    );

    signedRequest.endpoint = "/payments/admin";

    console.log(`Unauthorized endpoint: ${signedRequest.endpoint}`);

    console.log("\n4. Sending request to the proxy...");

    try {
      const response = await axios.post(
        `${PROXY_URL}/proxy/payment`,
        signedRequest
      );

      console.log("UNEXPECTED RESULT:");
      console.log(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.log("LATERAL MOVEMENT RESULT:");
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
      "\nUnauthorized-route test completed successfully."
    );
  } catch (error) {
    console.error(
      "\nLateral movement test failed:",
      error.response?.data || error.message
    );
  }
}

testLateralMovement();