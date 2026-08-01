const express = require("express");
const fs = require("fs");
const path = require("path");
const { randomUUID } = require("crypto");

const app = express();
const PORT = 3004;

const DATA_FILE = path.join(
  __dirname,
  "transactions.json"
);

app.use(express.json());

function readTransactions() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      return [];
    }

    const raw = fs.readFileSync(DATA_FILE, "utf8");

    return raw ? JSON.parse(raw) : [];
  } catch (error) {
    console.error(
      "Could not read transactions:",
      error.message
    );

    return [];
  }
}

function writeTransactions(transactions) {
  fs.writeFileSync(
    DATA_FILE,
    JSON.stringify(transactions, null, 2)
  );
}

app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "database-service",
    status: "healthy",
    storedTransactions:
      readTransactions().length,
  });
});

app.post("/transactions/store", (req, res) => {
  const {
    orderId,
    amount,
    currency,
    paymentId,
    paymentStatus,
  } = req.body || {};

  if (!orderId || !amount || !currency) {
    return res.status(400).json({
      success: false,
      message:
        "orderId, amount and currency are required",
    });
  }

  const transactions = readTransactions();

  const transaction = {
    transactionId: randomUUID(),
    orderId,
    amount: Number(amount),
    currency,
    paymentId: paymentId || null,
    paymentStatus:
      paymentStatus || "COMPLETED",
    storedAt: new Date().toISOString(),
  };

  transactions.unshift(transaction);
  writeTransactions(transactions);

  return res.status(201).json({
    success: true,
    message: "Transaction stored successfully",
    transaction,
  });
});

app.get("/transactions", (req, res) => {
  const transactions = readTransactions();

  res.json({
    success: true,
    count: transactions.length,
    transactions,
  });
});

app.listen(PORT, () => {
  console.log(
    `Database Service running at http://localhost:${PORT}`
  );
});