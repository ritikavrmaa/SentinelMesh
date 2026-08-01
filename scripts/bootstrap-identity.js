const axios = require("axios");
const fs = require("fs");
const path = require("path");

const IDENTITY_URL = "http://localhost:4001";

const credentialsPath = path.join(
  __dirname,
  "..",
  "services",
  "order-service",
  "credentials",
  "identity.json"
);

async function bootstrapIdentity() {
  try {
    console.log("Registering order-service...");

    const response = await axios.post(
      `${IDENTITY_URL}/register`,
      {
        serviceId: "order-service",
      }
    );

    fs.mkdirSync(path.dirname(credentialsPath), {
      recursive: true,
    });

    fs.writeFileSync(
      credentialsPath,
      JSON.stringify(response.data, null, 2)
    );

    console.log("order-service registered successfully.");
    console.log(`Credentials saved to: ${credentialsPath}`);
    console.log("Restart the Order Service.");
  } catch (error) {
    const message =
      error.response?.data?.error || error.message;

    if (message === "Service is already registered") {
      console.log("order-service is already registered.");
      console.log("No new credentials were generated.");
      console.log("Existing credentials remain unchanged.");
      return;
    }

    console.error("Identity bootstrap failed:", message);
    process.exit(1);
  }
}

bootstrapIdentity();