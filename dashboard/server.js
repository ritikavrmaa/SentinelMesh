const express = require("express");
const path = require("path");

const app = express();
const PORT = 5173;

const publicFolder = path.join(__dirname, "public");

app.use(express.static(publicFolder));

app.use((req, res) => {
  res.sendFile(path.join(publicFolder, "index.html"));
});

app.listen(PORT, () => {
  console.log(
    `SentinelMesh Dashboard running at http://localhost:${PORT}`
  );
});