# Real-Time Monitoring & Telemetry Architecture

## 1. Overview & Protocol Selection

In modern distributed serverless environments, visibility latency is paramount. Security operations centers (SOC) cannot wait minutes for batch log indexing to detect active privilege escalation or brute force attacks. The Serverless Security Verification Framework employs a low-overhead, browser-native **Server-Sent Events (SSE)** architecture paired with adaptive polling fallback to achieve sub-second event propagation without requiring heavy bi-directional WebSocket infrastructure.

---

## 2. Server-Sent Events (SSE) Channel Specification

### 2.1 Endpoint Specification
- **Primary Endpoint**: `/api/realtime/stream` (and `/api/v1/realtime/stream`)
- **Transport**: HTTP/1.1 or HTTP/2 with `Content-Type: text/event-stream`
- **Headers**:
  ```http
  HTTP/1.1 200 OK
  Content-Type: text/event-stream
  Cache-Control: no-cache, no-transform
  Connection: keep-alive
  X-Accel-Buffering: no
  ```

### 2.2 Event Stream Protocol & Data Format
The server pushes structured JSON messages across distinct event channels:

```
event: metric_update
data: {"activeUsers": 4, "totalInvocations": 182, "blockedThreats": 14, "avgLatencyMs": 1.42, "systemHealth": 98.6}

event: threat_alert
data: {"alertId": "alt-9821", "category": "SUSPICIOUS_FREQUENCY", "severity": "HIGH", "resource": "executeBatchTransfer", "timestamp": "2026-11-01T10:15:30.120Z"}

event: invocation_event
data: {"id": "inv-5542", "function": "getUserProfile", "decision": "ALLOW", "riskScore": 12, "executionTimeMs": 0.84}

event: heartbeat
data: {"timestamp": 1793528130000, "status": "ALIVE"}
```

---

## 3. Resilience, Heartbeats & Auto-Reconnect Mechanics

### 3.1 Client-Side Reconnection Strategy
The frontend `useRealtimeStream` React hook implements an exponential backoff reconnection algorithm with jitter to prevent reconnect storms against Cloudflare Workers edge nodes:

$$T_{\text{backoff}} = \min\left(T_{\text{max}}, \, T_{\text{initial}} \times 2^{\text{retryCount}}\right) \pm \text{jitter}$$

- $T_{\text{initial}} = 1000\text{ ms}$
- $T_{\text{max}} = 15000\text{ ms}$
- Reconnection attempts automatically resume when browser tab regains focus or network reconnects (`window.addEventListener('online', ...)`).

### 3.2 Edge Keep-Alive Heartbeat
To keep intermediary proxies and edge load balancers from terminating idle HTTP connections, the backend emits a `:keepalive` comment or `event: heartbeat` every 15 seconds.

### 3.3 Seamless Polling Fallback
If the browser or enterprise firewall rejects SSE connections (HTTP 502/504 or EventSource failure):
1. The client switches seamlessly to an adaptive polling mode (`/api/system/overview` and `/api/incidents` fetched every 3000 ms).
2. The UI displays a subtle indicator: `Real-time Mode: Long Polling (SSE Unavailable)`.
3. The client periodically retries the SSE stream every 60 seconds to upgrade back to push streaming.

---

## 4. Edge-Compatible In-Memory Event Hub

Because Cloudflare Workers can execute across 300+ edge locations, the event architecture leverages lightweight pub/sub primitives:
- On Node.js / Express development runtime: Uses an `EventEmitter` singleton broadcasting to all active client response streams.
- On Cloudflare Workers runtime: Utilizes a streaming `TransformStream` response pipeline, feeding real-time events generated during invocation lifecycles into the active client stream.

---

## 5. Security of Real-Time Streams

1. **Authentication Requirement**: Access to `/api/realtime/stream` requires a valid JWT token passed as either:
   - An `Authorization: Bearer <token>` header (via fetch EventSource polyfill), or
   - A short-lived ticket query parameter (`?stream_token=...`) validated against active server sessions.
2. **Channel-Level RBAC Filtering**: Events are filtered server-side based on user role:
   - `Super Administrator` & `Security Administrator`: Receive full forensic details including IP addresses and payload extracts.
   - `Viewer` & `Developer`: Receive sanitized metrics and function-level events scoped strictly to non-sensitive telemetry.
