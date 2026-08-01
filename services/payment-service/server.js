const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "payment-service",
    status: "healthy",
  });
});

app.post("/payments/charge", (req, res) => {
  const { orderId, amount } = req.body;

  if (!orderId || typeof amount !== "number") {
    return res.status(400).json({
      success: false,
      message: "orderId and numeric amount are required",
    });
  }

  res.json({
    success: true,
    message: "Payment processed successfully",
    payment: {
      paymentId: `PAY-${Date.now()}`,
      orderId,
      amount,
      status: "COMPLETED",
      processedBy: "payment-service",
      processedAt: new Date().toISOString(),
    },
  });
});

const PORT = 3003;

app.listen(PORT, () => {
  console.log(`Payment Service running at http://localhost:${PORT}`);
});