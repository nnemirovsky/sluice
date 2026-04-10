// openclaw-gateway-rpc.js
//
// Call an openclaw gateway JSON-RPC method from inside the openclaw
// container. Handles the full connect handshake (reads device identity,
// signs the payload with ed25519, sends connect, waits for hello-ok),
// then sends the requested method. Prints the JSON response and exits.
//
// Usage:
//   node openclaw-gateway-rpc.js <method> [<params-json>]
//   node openclaw-gateway-rpc.js wire-mcp <name> <url>
//
// Examples:
//   node openclaw-gateway-rpc.js secrets.reload
//   node openclaw-gateway-rpc.js config.patch \
//       '{"raw":"{\"mcp\":{\"servers\":{\"sluice\":{\"url\":\"http://sluice:3000/mcp\"}}}}","baseHash":"<hash>"}'
//   node openclaw-gateway-rpc.js wire-mcp sluice http://sluice:3000/mcp
//
// The "wire-mcp" convenience mode does: config.get to fetch the current
// hash, then config.patch to add the specified MCP server entry. This is
// the recommended way for sluice to register itself as an MCP gateway.
//
// This exists because the `openclaw` CLI hangs in container/non-TTY
// environments when used for these RPCs, and sluice needs to trigger
// them via `docker exec` at startup and after configuration changes.

const fs = require("fs");
const http = require("http");
const crypto = require("crypto");

const HOME = process.env.HOME || "/home/node";
const CONFIG_PATH = HOME + "/.openclaw/openclaw.json";
const IDENTITY_PATH = HOME + "/.openclaw/identity/device.json";
const PROTOCOL_VERSION = 3;
const CLIENT_ID = "cli";
const CLIENT_MODE = "cli";
const ROLE = "operator";
const PLATFORM = "linux";
const DEVICE_FAMILY = "Linux";
const TIMEOUT_MS = 15000;

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

// Parse script arguments. The script can be invoked two ways:
//   1. `node script.js foo bar` => argv = [node, script.js, foo, bar]
//   2. `node -e "<script>" foo bar` => argv = [node, foo, bar]
// sluice uses (2) because it embeds this script into its binary and
// passes it to `node -e`. Auto-detect by checking whether argv[1] ends
// in .js so the script also works standalone for debugging.
const argStart = /\.js$/.test(process.argv[1] || "") ? 2 : 1;
const method = process.argv[argStart];
if (!method) {
  fail("usage: openclaw-gateway-rpc.js <method> [<params-json>] | wire-mcp <name> <url>");
}

// wire-mcp: convenience mode that chains config.get (to read current
// hash) -> config.patch (to merge mcp.servers.<name> = {url}).
const wireMcpMode = method === "wire-mcp";
let wireMcpName = null;
let wireMcpURL = null;
if (wireMcpMode) {
  wireMcpName = process.argv[argStart + 1];
  wireMcpURL = process.argv[argStart + 2];
  if (!wireMcpName || !wireMcpURL) {
    fail("usage: openclaw-gateway-rpc.js wire-mcp <name> <url>");
  }
}

const params =
  !wireMcpMode && process.argv[argStart + 1]
    ? JSON.parse(process.argv[argStart + 1])
    : undefined;

// Read gateway port and auth token from openclaw.json.
let port = 18789;
let token = "";
try {
  const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  port = cfg.gateway?.port || 18789;
  token = cfg.gateway?.auth?.token || "";
} catch (err) {
  fail(`read ${CONFIG_PATH}: ${err.message}`);
}

// Read device identity (ed25519 keypair + deviceId).
let identity;
try {
  identity = JSON.parse(fs.readFileSync(IDENTITY_PATH, "utf8"));
} catch (err) {
  fail(`read ${IDENTITY_PATH}: ${err.message}`);
}

// publicKeyRawBase64Url: derive raw 32-byte public key from PEM, encode as
// URL-safe base64 without padding (matches openclaw's format).
function pemToRawPublicKey(pem) {
  const key = crypto.createPublicKey(pem);
  const der = key.export({ type: "spki", format: "der" });
  // SPKI for Ed25519 is 44 bytes: 12-byte header + 32-byte raw key.
  return der.subarray(der.length - 32);
}

function base64UrlEncode(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function signPayload(privateKeyPem, payload) {
  const key = crypto.createPrivateKey(privateKeyPem);
  const sig = crypto.sign(null, Buffer.from(payload, "utf8"), key);
  return base64UrlEncode(sig);
}

// normalizeMetadata matches openclaw's normalizeDeviceMetadataForAuth:
// trim and lowercase ASCII only. The server applies this to platform
// and deviceFamily before signature verification, so the client must
// sign with the normalized form.
function normalizeMetadata(value) {
  if (typeof value !== "string") {
    return "";
  }
  const trimmed = value.trim();
  return trimmed.replace(/[A-Z]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) + 32));
}

// buildDeviceAuthPayloadV3 matches openclaw's format in
// src/gateway/device-auth.ts: pipe-separated fields in a fixed order.
function buildPayloadV3(p) {
  return [
    "v3",
    p.deviceId,
    p.clientId,
    p.clientMode,
    p.role,
    p.scopes.join(","),
    String(p.signedAtMs),
    p.token || "",
    p.nonce,
    normalizeMetadata(p.platform),
    normalizeMetadata(p.deviceFamily),
  ].join("|");
}

// WebSocket framing: build a masked client frame for the given text payload.
function makeFrame(text) {
  const p = Buffer.from(text, "utf8");
  const mask = crypto.randomBytes(4);
  let header;
  if (p.length < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x81; // FIN + text
    header[1] = 0x80 | p.length;
  } else if (p.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(p.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(p.length), 2);
  }
  const masked = Buffer.alloc(p.length);
  for (let i = 0; i < p.length; i++) {
    masked[i] = p[i] ^ mask[i % 4];
  }
  return Buffer.concat([header, mask, masked]);
}

// Minimal WebSocket parser: pulls complete text frames out of a rolling
// buffer. Control frames (ping/pong/close) are ignored; binary frames
// are not expected from the gateway.
function parseFrames(buf) {
  const msgs = [];
  let i = 0;
  while (i < buf.length) {
    if (i + 2 > buf.length) break;
    const opcode = buf[i] & 0x0f;
    let payloadLen = buf[i + 1] & 0x7f;
    let offset = i + 2;
    if (payloadLen === 126) {
      if (offset + 2 > buf.length) break;
      payloadLen = buf.readUInt16BE(offset);
      offset += 2;
    } else if (payloadLen === 127) {
      if (offset + 8 > buf.length) break;
      payloadLen = Number(buf.readBigUInt64BE(offset));
      offset += 8;
    }
    if (offset + payloadLen > buf.length) break;
    const data = buf.slice(offset, offset + payloadLen);
    if (opcode === 1) {
      msgs.push(data.toString("utf8"));
    }
    i = offset + payloadLen;
  }
  return { msgs, rest: buf.slice(i) };
}

const wsKey = crypto.randomBytes(16).toString("base64");
const req = http.request({
  hostname: "127.0.0.1",
  port,
  path: "/",
  headers: {
    Upgrade: "websocket",
    Connection: "Upgrade",
    "Sec-WebSocket-Key": wsKey,
    "Sec-WebSocket-Version": "13",
    Authorization: "Bearer " + token,
  },
});

const connectId = crypto.randomUUID();
const getId = crypto.randomUUID();
const methodId = crypto.randomUUID();
let step = "waiting-challenge";

req.on("upgrade", (_res, socket) => {
  let buf = Buffer.alloc(0);
  const deadline = setTimeout(() => {
    fail(`timeout at step ${step}`);
  }, TIMEOUT_MS);

  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    const parsed = parseFrames(buf);
    buf = parsed.rest;
    for (const text of parsed.msgs) {
      let obj;
      try {
        obj = JSON.parse(text);
      } catch {
        continue;
      }

      if (step === "waiting-challenge" && obj.type === "event" && obj.event === "connect.challenge") {
        const nonce = obj.payload?.nonce;
        if (!nonce) {
          fail("connect.challenge missing nonce");
        }
        const signedAtMs = Date.now();
        // Claim operator.admin scope: required for config.patch and
        // secrets.reload. The server verifies the signature with the
        // claimed scopes and then checks whether the paired device is
        // authorized for those scopes. Unpaired devices would be
        // rejected here.
        const scopes = ["operator.admin"];
        const payload = buildPayloadV3({
          deviceId: identity.deviceId,
          clientId: CLIENT_ID,
          clientMode: CLIENT_MODE,
          role: ROLE,
          scopes,
          signedAtMs,
          token,
          nonce,
          platform: PLATFORM,
          deviceFamily: DEVICE_FAMILY,
        });
        const signature = signPayload(identity.privateKeyPem, payload);
        const publicKeyRaw = base64UrlEncode(pemToRawPublicKey(identity.publicKeyPem));

        const connectReq = {
          type: "req",
          id: connectId,
          method: "connect",
          params: {
            minProtocol: PROTOCOL_VERSION,
            maxProtocol: PROTOCOL_VERSION,
            client: {
              id: CLIENT_ID,
              version: "0.0.0",
              platform: PLATFORM,
              deviceFamily: DEVICE_FAMILY,
              mode: CLIENT_MODE,
            },
            role: ROLE,
            scopes,
            auth: { token },
            device: {
              id: identity.deviceId,
              publicKey: publicKeyRaw,
              signature,
              signedAt: signedAtMs,
              nonce,
            },
          },
        };
        step = "sent-connect";
        socket.write(makeFrame(JSON.stringify(connectReq)));
      } else if (step === "sent-connect" && obj.type === "res" && obj.id === connectId) {
        if (!obj.ok) {
          clearTimeout(deadline);
          fail(`connect failed: ${JSON.stringify(obj.error)}`);
        }
        if (wireMcpMode) {
          // Step 1 of wire-mcp: fetch current config hash.
          step = "sent-get";
          socket.write(
            makeFrame(JSON.stringify({ type: "req", id: getId, method: "config.get" })),
          );
        } else {
          step = "sent-method";
          const methodReq = { type: "req", id: methodId, method };
          if (params !== undefined) {
            methodReq.params = params;
          }
          socket.write(makeFrame(JSON.stringify(methodReq)));
        }
      } else if (step === "sent-get" && obj.type === "res" && obj.id === getId) {
        if (!obj.ok) {
          clearTimeout(deadline);
          fail(`config.get failed: ${JSON.stringify(obj.error)}`);
        }
        const baseHash = obj.payload?.hash;
        if (!baseHash) {
          clearTimeout(deadline);
          fail("config.get response missing hash");
        }
        // Step 2 of wire-mcp: merge-patch mcp.servers.<name> = {url}.
        // restartDelayMs gives us time to receive the response and exit
        // cleanly before the gateway restarts and kills our docker exec
        // (which would otherwise result in exit code 137).
        const raw = JSON.stringify({
          mcp: { servers: { [wireMcpName]: { url: wireMcpURL } } },
        });
        step = "sent-method";
        socket.write(
          makeFrame(
            JSON.stringify({
              type: "req",
              id: methodId,
              method: "config.patch",
              params: { raw, baseHash, restartDelayMs: 3000 },
            }),
          ),
        );
      } else if (step === "sent-method" && obj.type === "res" && obj.id === methodId) {
        clearTimeout(deadline);
        if (!obj.ok) {
          console.error(
            `${wireMcpMode ? "config.patch" : method} failed:`,
            JSON.stringify(obj.error),
          );
          process.exit(1);
        }
        // Success. Print the payload as JSON so callers can parse it.
        process.stdout.write(JSON.stringify(obj.payload ?? null));
        process.exit(0);
      }
    }
  });

  socket.on("error", (err) => {
    clearTimeout(deadline);
    fail(`socket error: ${err.message}`);
  });
});

req.on("error", (err) => fail(`http error: ${err.message}`));
req.setTimeout(TIMEOUT_MS, () => {
  req.destroy();
  fail("http request timeout");
});
req.end();
