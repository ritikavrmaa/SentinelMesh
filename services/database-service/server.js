const express = require("express");
const fs = require("fs");
const path = require("path");
const { randomUUID } = require("crypto");
const cors = require("cors");

const app = express();
const PORT = 3004;

const DATA_FILE = path.join(
  __dirname,
  "transactions.json"
);

app.use(cors());
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
  const transactions = readTransactions();

  return res.json({
    success: true,
    service: "database-service",
    status: "healthy",
    storedTransactions: transactions.length,
  });
});

app.post("/transactions/store", (req, res) => {
  try {
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

    const numericAmount = Number(amount);

    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: "amount must be a valid positive number",
      });
    }

    const transactions = readTransactions();

    const transaction = {
      transactionId: randomUUID(),
      orderId,
      amount: numericAmount,
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
  } catch (error) {
    console.error(
      "Could not store transaction:",
      error.message
    );

    return res.status(500).json({
      success: false,
      message: "Unable to store transaction",
    });
  }
});

app.get("/transactions", (req, res) => {
  try {
    const transactions = readTransactions();

    return res.json({
      success: true,
      count: transactions.length,
      transactions,
    });
  } catch (error) {
    console.error(
      "Could not fetch transactions:",
      error.message
    );

    return res.status(500).json({
      success: false,
      message: "Unable to fetch transactions",
      count: 0,
      transactions: [],
    });
  }
});

app.delete("/transactions", (req, res) => {
  try {
    writeTransactions([]);

    return res.json({
      success: true,
      message: "All transactions cleared successfully",
      count: 0,
      transactions: [],
    });
  } catch (error) {
    console.error(
      "Could not clear transactions:",
      error.message
    );

    return res.status(500).json({
      success: false,
      message: "Unable to clear transactions",
    });
  }
});

app.listen(PORT, () => {
  console.log(
    `Database Service running on port ${PORT}`
  );
});