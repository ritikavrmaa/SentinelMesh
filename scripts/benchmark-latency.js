const axios = require("axios");

const ORDER_SERVICE_URL = "http://localhost:3002";
const PROXY_URL = "http://localhost:4000";

const WARMUP_REQUESTS = 5;
const BENCHMARK_REQUESTS = 50;

function calculateAverage(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function calculateMedian(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);

  if (sorted.length % 2 === 0) {
    return (sorted[middle - 1] + sorted[middle]) / 2;
  }

  return sorted[middle];
}

function calculatePercentile(values, percentile) {
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil((percentile / 100) * sorted.length) - 1;

  return sorted[Math.max(0, index)];
}

function round(value) {
  return Number(value.toFixed(3));
}

async function createSignedRequest(index) {
  const response = await axios.post(
    `${ORDER_SERVICE_URL}/create-payment-request`,
    {
      orderId: `ORD-BENCH-${String(index).padStart(3, "0")}`,
      amount: 2000,
    }
  );

  return response.data.request;
}

async function sendRequest(index) {
  const signedRequest = await createSignedRequest(index);

  const response = await axios.post(
    `${PROXY_URL}/proxy/payment`,
    signedRequest
  );

  return {
    verificationLatencyMs: response.data.verificationLatencyMs,
    upstreamLatencyMs: response.data.upstreamLatencyMs,
    totalLatencyMs: response.data.totalLatencyMs,
    cacheStatus: response.data.publicKeyCacheStatus,
  };
}

function buildStatistics(values) {
  return {
    averageMs: round(calculateAverage(values)),
    medianMs: round(calculateMedian(values)),
    p95Ms: round(calculatePercentile(values, 95)),
    maximumMs: round(Math.max(...values)),
    minimumMs: round(Math.min(...values)),
  };
}

async function runBenchmark() {
  try {
    console.log("\nSentinelMesh Latency Benchmark");
    console.log("==============================");

    console.log("\n1. Requesting a fresh access token...");

    await axios.post(`${ORDER_SERVICE_URL}/auth/token`);

    console.log("Fresh token received.");

    console.log(
      `\n2. Running ${WARMUP_REQUESTS} warm-up requests...`
    );

    for (let index = 1; index <= WARMUP_REQUESTS; index++) {
      const result = await sendRequest(`WARM-${index}`);

      console.log(
        `Warm-up ${index}: verification=${result.verificationLatencyMs}ms, ` +
          `cache=${result.cacheStatus}`
      );
    }

    console.log(
      `\n3. Running ${BENCHMARK_REQUESTS} measured requests...`
    );

    const verificationResults = [];
    const upstreamResults = [];
    const totalResults = [];

    for (let index = 1; index <= BENCHMARK_REQUESTS; index++) {
      const result = await sendRequest(index);

      verificationResults.push(result.verificationLatencyMs);
      upstreamResults.push(result.upstreamLatencyMs);
      totalResults.push(result.totalLatencyMs);

      console.log(
        `Request ${String(index).padStart(2, "0")}: ` +
          `verification=${result.verificationLatencyMs}ms, ` +
          `upstream=${result.upstreamLatencyMs}ms, ` +
          `total=${result.totalLatencyMs}ms, ` +
          `cache=${result.cacheStatus}`
      );
    }

    const report = {
      generatedAt: new Date().toISOString(),
      warmupRequests: WARMUP_REQUESTS,
      measuredRequests: BENCHMARK_REQUESTS,
      targetVerificationLatencyMs: 15,
      verification: buildStatistics(verificationResults),
      upstream: buildStatistics(upstreamResults),
      total: buildStatistics(totalResults),
    };

    report.targetPassed =
      report.verification.p95Ms <=
      report.targetVerificationLatencyMs;

    console.log("\n4. Benchmark Summary");
    console.log("====================");

    console.log(JSON.stringify(report, null, 2));

    console.log(
      report.targetPassed
        ? "\nPASS: p95 verification latency is within 15 ms."
        : "\nFAIL: p95 verification latency exceeds 15 ms."
    );
  } catch (error) {
    console.error(
      "\nBenchmark failed:",
      error.response?.data || error.message
    );

    process.exitCode = 1;
  }
}

runBenchmark();