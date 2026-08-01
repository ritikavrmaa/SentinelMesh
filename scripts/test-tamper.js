const axios = require("axios");

const ORDER_SERVICE_URL = "http://localhost:3002";
const PROXY_URL = "http://localhost:4000";

async function testTamperedRequest() {
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
        orderId: "ORD-TAMPER-001",
        amount: 2000,
      }
    );

    const signedRequest = signedResponse.data.request;

    console.log(`Original amount: ${signedRequest.body.amount}`);

    console.log(
      "\n3. Tampering with the amount after the request was signed..."
    );

    signedRequest.body.amount = 9000;

    console.log(`Tampered amount: ${signedRequest.body.amount}`);

    console.log("\n4. Sending tampered request to the proxy...");

    try {
      const response = await axios.post(
        `${PROXY_URL}/proxy/payment`,
        signedRequest
      );

      console.log("UNEXPECTED RESULT:");
      console.log(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.log("TAMPERED REQUEST RESULT:");
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
      "\nTampered-request test completed successfully."
    );
  } catch (error) {
    console.error(
      "\nTamper test failed:",
      error.response?.data || error.message
    );
  }
}

testTamperedRequest();