require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 5173);

const publicFolder = path.join(__dirname, "public");

app.use(express.json({ limit: "200kb" }));

const SERVICE_URLS = {
  proxy:
    process.env.CORE_INTERNAL_URL ||
    "http://localhost:4000",

  user:
    process.env.USER_INTERNAL_URL ||
    "http://localhost:3001",

  order:
    process.env.ORDER_INTERNAL_URL ||
    "http://localhost:3002",

  database:
    process.env.DATABASE_INTERNAL_URL ||
    "http://localhost:3004",
};

function createServiceProxy(serviceName, prefix) {
  app.use(prefix, async (req, res) => {
    try {
      const baseUrl = SERVICE_URLS[serviceName];

      const forwardedPath =
        req.originalUrl.slice(prefix.length) || "/";

      const targetUrl =
        `${baseUrl}${forwardedPath}`;

      const headers = {
        Accept: "application/json",
      };

      const options = {
        method: req.method,
        headers,
      };

      if (
        !["GET", "HEAD"].includes(req.method) &&
        req.body !== undefined
      ) {
        headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(req.body);
      }

      const upstreamResponse =
        await fetch(targetUrl, options);

      const responseText =
        await upstreamResponse.text();

      res.status(upstreamResponse.status);

      const contentType =
        upstreamResponse.headers.get("content-type");

      if (contentType) {
        res.setHeader("Content-Type", contentType);
      }

      return res.send(responseText);
    } catch (error) {
      console.error(
        `${serviceName} proxy error:`,
        error
      );

      return res.status(502).json({
        success: false,
        error: `${serviceName} service unavailable`,
      });
    }
  });
}

createServiceProxy("proxy", "/api/proxy");
createServiceProxy("user", "/api/user");
createServiceProxy("order", "/api/order");
createServiceProxy("database", "/api/database");

app.post("/api/lyzr/analyze", async (req, res) => {
  try {
    const { auditEvent } = req.body;

    if (
      !auditEvent ||
      typeof auditEvent !== "object"
    ) {
      return res.status(400).json({
        success: false,
        error: "A valid auditEvent object is required.",
      });
    }

    const {
      LYZR_API_URL,
      LYZR_API_KEY,
      LYZR_AGENT_ID,
      LYZR_USER_ID,
    } = process.env;

    if (
      !LYZR_API_URL ||
      !LYZR_API_KEY ||
      !LYZR_AGENT_ID ||
      !LYZR_USER_ID
    ) {
      return res.status(500).json({
        success: false,
        error:
          "Lyzr environment variables are missing.",
      });
    }

    const sessionId =
      `sentinelmesh-${Date.now()}-${crypto
        .randomBytes(4)
        .toString("hex")}`;

    const lyzrResponse = await fetch(
      LYZR_API_URL,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": LYZR_API_KEY,
        },
        body: JSON.stringify({
          user_id: LYZR_USER_ID,
          agent_id: LYZR_AGENT_ID,
          session_id: sessionId,
          message: JSON.stringify(
            auditEvent,
            null,
            2
          ),
        }),
      }
    );

    const responseText =
      await lyzrResponse.text();

    let responseData;

    try {
      responseData =
        JSON.parse(responseText);
    } catch {
      responseData = {
        response: responseText,
      };
    }

    if (!lyzrResponse.ok) {
      return res
        .status(lyzrResponse.status)
        .json({
          success: false,
          error:
            responseData.detail ||
            responseData.message ||
            "Lyzr analysis failed.",
        });
    }

    return res.json({
      success: true,
      sessionId,
      analysis:
        responseData.response ||
        responseData.message ||
        responseData.output ||
        responseData,
    });
  } catch (error) {
    console.error(
      "AI analysis error:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        "Unable to generate AI security analysis.",
    });
  }
});

app.get("/api/lyzr/status", (req, res) => {
  res.json({
    configured: Boolean(
      process.env.LYZR_API_URL &&
      process.env.LYZR_API_KEY &&
      process.env.LYZR_AGENT_ID &&
      process.env.LYZR_USER_ID
    ),
  });
});

app.get("/dashboard-health", (req, res) => {
  res.json({
    success: true,
    service: "SentinelMesh Dashboard",
    status: "healthy",
  });
});

app.use(express.static(publicFolder));

app.use((req, res) => {
  res.sendFile(
    path.join(publicFolder, "index.html")
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `SentinelMesh Dashboard running on port ${PORT}`
  );

  console.log(
    `Core URL: ${SERVICE_URLS.proxy}`
  );
});