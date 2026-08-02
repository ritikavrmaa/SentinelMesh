
require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.DASHBOARD_PORT || 5173;

const publicFolder = path.join(__dirname, "public");

app.use(express.json({ limit: "100kb" }));
app.use(express.static(publicFolder));

app.post("/api/lyzr/analyze", async (req, res) => {
  try {
    const { auditEvent } = req.body;

    if (!auditEvent || typeof auditEvent !== "object") {
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
        error: "Lyzr environment variables are missing.",
      });
    }

    const sessionId = `sentinelmesh-${Date.now()}-${crypto
      .randomBytes(4)
      .toString("hex")}`;

    const lyzrResponse = await fetch(LYZR_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": LYZR_API_KEY,
      },
      body: JSON.stringify({
        user_id: LYZR_USER_ID,
        agent_id: LYZR_AGENT_ID,
        session_id: sessionId,
        message: JSON.stringify(auditEvent, null, 2),
        system_prompt_variables: {},
        filter_variables: {},
        features: [],
      }),
    });

    const responseText = await lyzrResponse.text();

    let responseData;

    try {
      responseData = JSON.parse(responseText);
    } catch {
      responseData = { response: responseText };
    }

    if (!lyzrResponse.ok) {
      console.error("Lyzr API error:", responseData);

      return res.status(lyzrResponse.status).json({
        success: false,
        error:
          responseData.detail ||
          responseData.message ||
          "Lyzr analysis request failed.",
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
    console.error("AI analysis error:", error);

    return res.status(500).json({
      success: false,
      error: "Unable to generate AI security analysis.",
    });
  }
});

app.get("/api/lyzr/status", (req, res) => {
  const configured = Boolean(
    process.env.LYZR_API_URL &&
      process.env.LYZR_API_KEY &&
      process.env.LYZR_AGENT_ID &&
      process.env.LYZR_USER_ID
  );

  res.json({
    configured,
    agent: configured ? "SentinelMesh AI Security Analyst" : null,
  });
});

app.use((req, res) => {
  res.sendFile(path.join(publicFolder, "index.html"));
});

app.listen(PORT, () => {
  console.log(`SentinelMesh Dashboard running at http://localhost:${PORT}`);
  console.log(
    `Lyzr AI integration: ${
      process.env.LYZR_API_KEY ? "configured" : "not configured"
    }`
  );
});