@echo off
cd /d D:\work\SentinelMesh

echo Starting SentinelMesh services...

start "SentinelMesh Identity" cmd /k node identity-service\server.js
timeout /t 1 /nobreak >nul

start "SentinelMesh Proxy" cmd /k node zero-trust-proxy\server.js
timeout /t 1 /nobreak >nul

start "SentinelMesh User" cmd /k node services\user-service\server.js
start "SentinelMesh Order" cmd /k node services\order-service\server.js
start "SentinelMesh Payment" cmd /k node services\payment-service\server.js
start "SentinelMesh Database" cmd /k node services\database-service\server.js
start "SentinelMesh Dashboard" cmd /k node dashboard\server.js

echo.
echo SentinelMesh services launched in separate terminals.
echo Dashboard: http://localhost:5173