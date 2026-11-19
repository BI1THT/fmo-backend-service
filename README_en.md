# FMO Server Authorizer Service

> [中文](README.md)

**v1.1.1** | .NET 10.0 | Ed25519 | CBOR | Self-contained Single Binary

---

FMO (FM Over Internet) Server Authorizer Service is a standalone device authenticator designed specifically for the amateur radio FMO digital communication network.

It implements fully offline, decentralized device identity verification through a three-layer certificate chain: **Root CA → Intermediate CA → User/Device Certificate**. No real-time authoritative center is required — every amateur radio enthusiast can securely deploy their own server, building a true zero-trust authentication model in the ham radio world.

```
Device ──MQTT CONNECT──▶ EMQX Broker ──POST /auth──▶ SAS
  (username+password)         HTTP Callback          Cert Chain Verify + ACL
```

---

## Why Do You Need It?

Traditional digital communication networks (such as D-Star, YSF, etc.) typically rely on centralized authentication servers to verify device identity. This creates several pain points:

| Pain Point | Description |
|------------|-------------|
| **Single Point of Failure** | Central service goes down → all users locked out |
| **Ongoing Maintenance** | Requires 24/7 dedicated ops for auth infrastructure |
| **External Dependencies** | Individuals or small groups struggle to build independent trusted networks |

FMO Server Authorizer Service shifts the trust anchor from "a central server on the network" down to "the root certificate in your hands", making decentralized secure authentication a reality.

## Core Concept: Three-Layer Certificate Chain

This service adopts the classic PKI (Public Key Infrastructure) trust model:

```
Root Certificate (Root CA)
 └─ Intermediate Certificate (Intermediate CA)
     └─ User/Device Certificate
```

- **Root Certificate** – The ultimate trust anchor, securely stored offline by the network creator, typically does not directly issue user certificates.
- **Intermediate Certificate** – Issued by the Root CA, used for day-to-day user and device management, can be periodically rotated or issued per subnet.
- **User/Device Certificate** – Issued by the Intermediate CA, bound to a specific radio device or operator callsign, used for identity proof on every connection.

The verification process is entirely offline: the authenticator only needs to load root certificates at startup, then independently validates any FMO device's legitimate identity by checking the certificate chain's signatures, validity periods, and revocation status — no online database queries needed.

## Zero-Trust Authentication Model

Here "zero-trust" means **"never trust, always verify"**:

- Don't trust network location (whether the request comes from intranet or public internet)
- Don't trust session state (no "authenticate once, valid forever" tokens)
- Every connection request must carry a valid device certificate, independently verified by this service

Only devices holding legitimate certificates can establish communication. Security is guaranteed even in partially untrusted network environments.

## Features

- Fully Offline Verification – No internet connection needed, pure local certificate chain validation
- Zero-Trust Architecture – Every connection is forcibly verified, unauthorized devices cannot connect
- Lightweight & Easy to Deploy – Single binary, simple configuration, suitable for embedded or lightweight servers
- Three-Layer PKI Chain – Root CA → Intermediate CA → User Cert
- Ed25519 High-Performance Signatures – Modern elliptic curve, secure and fast
- CBOR Compact Encoding – More compact than JSON, suitable for embedded scenarios
- CRL Revocation Lists – Certificate revocation checking with periodic refresh
- Login Audit Archive – Full login payloads archived per callsign; logs include Root SN and request ID
- EMQX HTTP Auth Integration – Plug-and-play as EMQX Broker authentication callback
- Cluster Support – Multiple MQTT Brokers sharing a single SAS instance for authentication
- OTA Auto-Update – Built-in version checking and automatic upgrades
- Cross-Platform – Windows / Linux / macOS (x64 & ARM64)
- Docker Compose Deployment – Orchestrates SAS and EMQX together with an internal HTTP authentication callback
- Persistent Runtime Configuration – `sas-data` and `emqx-data` volumes retain configuration, certificates, and broker data
- Image-Based Updates – Pull the latest GHCR image and let Compose recreate services as needed, reducing manual work and service recovery time

## Typical Deployment Scenarios

### Personal FMO Gateway

Generate your own root certificate and issue certificates for your home FMO devices. Only your own devices can connect.

### Club Shared Reflector

The club administrator holds the root certificate, issues intermediate and user certificates for members. Members connect to club resources using their certificates.

### Emergency Communication Field Network

When setting up a temporary emergency network, the field commander quickly generates a certificate hierarchy. All participating stations securely mesh using pre-provisioned certificates, with no dependence on external networks.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | .NET 10.0 (self-contained, no installation required) |
| Signature Algorithm | Ed25519 ([Chaos.NaCl](https://www.nuget.org/packages/Chaos.NaCl.Standard)) |
| Serialization | CBOR ([System.Formats.Cbor](https://www.nuget.org/packages/System.Formats.Cbor)) |
| HTTP Server | HttpListener (built-in) |
| Distribution | Single-file self-contained binary (PublishSingleFile) |

---

## Installation

### From Device Dashboard (Recommended)

The FMO device management dashboard provides one-click installation scripts with pre-configured parameters for your platform.

### Download Pre-built Binaries

Download for your platform from Releases:

| Platform | File | Notes |
|----------|------|-------|
| Windows x64 | `sas-win-x64.zip` | Extract and double-click `Sas.exe` |
| Linux x64 | `sas-linux-x64.tar.gz` | `tar xzf` then run `./Sas` |
| Linux ARM64 | `sas-linux-arm64.tar.gz` | Raspberry Pi, etc. |
| macOS Apple Silicon | `sas-osx-arm64.tar.gz` | M1/M2/M3/M4, run `./Sas` in terminal |
| macOS Intel | `sas-osx-x64.tar.gz` | Intel Mac |

No .NET installation required — extract and run.

### Build from Source

```bash
# Build all platforms (outputs to bin/)
./scripts/publish.ps1

# Build single platform (self-contained, no .NET runtime needed)
dotnet publish src/Sas.csproj -c Release -r <RID> --self-contained -p:PublishSingleFile=true -o out
```

Supported RIDs (Runtime Identifiers):

| RID | Platform |
|-----|----------|
| `win-x64` | Windows x64 |
| `linux-x64` | Linux x64 |
| `linux-arm64` | Linux ARM64 |
| `osx-arm64` | macOS Apple Silicon |
| `osx-x64` | macOS Intel |

---

## Quick Start

### Windows Desktop

```
Double-click Sas.exe → Interactive setup → Auto-start
```

Subsequent launches start directly without reconfiguration.

### Linux Command Line

```bash
# First run (writes config)
./Sas --server-uid 12345 --server-callsign BG5ESN \
      --mqtt-host your-mqtt-broker.com --cert-fingerprint gjJGc7...base64url...xY

# Subsequent runs (config persisted at ~/.sas/config.json)
./Sas
```

### Verify Service is Running

```bash
curl -X POST http://127.0.0.1:8080/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"BG6VMZ","password":"...base64url..."}'
# → {"result":"deny"} (denied without valid cert = service is working)
```

---

## Docker Compose Deployment

The included `docker-compose.yml` starts SAS and EMQX together. EMQX and SAS share an internal Docker network, and the HTTP authenticator is preconfigured to call `http://sas:8080/auth`; no additional Dashboard authentication setup is required.

```bash
# Create the deployment configuration and set the server UID, callsign,
# certificate fingerprint, and EMQX Dashboard password.
cp .env.example .env

# Start SAS and EMQX.
docker compose up -d

# View service logs.
docker compose logs -f sas emqx
```

On Windows PowerShell, use:

```powershell
Copy-Item .env.example .env
```

Published ports:

| Service | Address | Purpose |
|---------|---------|---------|
| EMQX MQTT | `tcp://<server>:1883` | FMO device connections |
| EMQX Dashboard | `http://<server>:18083` | Sign in with the Dashboard credentials in `.env` |

The SAS HTTP authentication port is exposed only on the internal Compose network and is not reachable directly from the host. The `sas-data` volume persists SAS configuration and root certificates, while `emqx-data` persists EMQX data. Do not remove these volumes unless you intend to fully reinitialize the deployment.

To update, pull the latest images and let Compose recreate only services that require an update:

```bash
docker compose pull
docker compose up -d
```

This two-command workflow avoids manually stopping, deleting, and recreating containers, reducing maintenance operations and service recovery time. A single-instance service still has a brief connection interruption while it is recreated.

---

## EMQX Configuration

Configure HTTP Password Authentication in EMQX Dashboard:

```
Auth Type: Password-Based
Auth Mechanism: HTTP
Method: POST
URL: http://<sas-host>:8080/auth
Headers: { "content-type": "application/json" }
Body: { "username": "${username}", "password": "${password}" }
```

---

## Configuration Reference

On first run, SAS writes configuration to `~/.sas/config.json` (Windows: `%USERPROFILE%\.sas\config.json`). This file is the single source of truth — no arguments needed on subsequent launches.

### config.json Structure

```json
{
  "server": {
    "uid": 0,
    "callsign": "",
    "issuerSn": 0,
    "certFingerprint": "",
    "admins": [{ "uid": 0, "certFingerprint": "", "role": "admin" }]
  },
  "mqtt": {
    "host": "",
    "port": 1883,
    "clusters": [{"uid": 0, "callsign": "", "mqtt_host": "", "mqtt_port": 1883, "certFingerprint": ""}]
  },
  "trust": { "allowIssuerSn": [], "rootsDir": "~/.sas/roots" },
  "crl": { "refreshSec": 14400, "mode": "soft" },
  "http": {
    "addr": "0.0.0.0",
    "port": 8080,
    "ttlSec": 14400,
    "responseTemplate": "emqx",
    "maxBodyBytes": 65536,
    "maxPasswordBytes": 32768,
    "maxConcurrent": 128,
    "rateLimit": {
      "enabled": true,
      "globalPerMinute": 600,
      "breakerEnabled": true,
      "breakerFailures": 20,
      "breakerWindowSec": 300,
      "breakerBanSec": 600
    }
  },
  "update": { "enabled": true },
  "log": { "level": "Info" },
  "archive": {
    "enabled": true,
    "dir": "/data/sas/archive",
    "recordDenied": true,
    "recordDeniedPayload": false,
    "deniedPayloadSampleRate": 0.0,
    "retentionDays": 30,
    "maxFileBytes": 16777216,
    "maxRecordBytes": 16384
  }
}
```

### Required Fields

| Field | Description | Source |
|-------|-------------|--------|
| `server.uid` | Server unique ID | FMO management dashboard |
| `server.callsign` | Server callsign | Same, e.g. `BG5ESN` |
| `mqtt.host` | MQTT Broker address | Your Broker IP or domain |
| `server.certFingerprint` | Server cert SHA-256 fingerprint (base64url) | FMO dashboard "Certificate Fingerprint" |

### CLI Arguments

| Argument | Config Field | Default |
|----------|-------------|:-------:|
| `--server-uid` | `server.uid` | Required |
| `--server-callsign` | `server.callsign` | Required |
| `--mqtt-host` | `mqtt.host` | Required |
| `--cert-fingerprint` | `server.certFingerprint` | Required |
| `--mqtt-port` | `mqtt.port` | 1883 |
| `--http-port` | `http.port` | 8080 |
| `--http-addr` | `http.addr` | 0.0.0.0 |
| `--http-ttl` | `http.ttlSec` | 14400 |
| `--allow-issuer-sn` | `trust.allowIssuerSn` | All |
| `--roots-dir` | `trust.rootsDir` | `~/.sas/roots` |
| `--issuer-sn` | `server.issuerSn` | 0 |
| `--crl-refresh` | `crl.refreshSec` | 14400 |
| `--crl-mode` | `crl.mode` | soft |
| `--log-level` | `log.level` | Info |
| `--archive-dir` | `archive.dir` | `~/.sas/archive` |
| `--archive-retention` | `archive.retentionDays` | 30 |

> **Config Hot-Update**: When `~/.sas/config.json` already exists, launching with CLI arguments will automatically update the corresponding fields and save — no manual editing required.

### Login Audit & Archive

Every HTTP authentication produces a structured log line. Successful logins store the complete signed payload; failed logins store a summary by default to keep high-frequency failures from filling the disk.

The log shows which Root CA and Intermediate CA issued the user certificate, plus a request ID that links the line to its archive record:

```text
[INFO ] HTTP auth: allow callsign=BG6VMZ rootSn=1 rootFp=1a2b3c4d rootName=BG5ESN issuerSn=1001 issuerFp=7f8e9d0c issuerName=bd4wpw payloadLen=3120 payloadSha256=3f2a9c1d4b5e6f70 passwordLen=4160 req=a1b2c3d4e5f6
[WARN ] HTTP auth: deny callsign=BG6VMZ rootSn=1 rootFp=1a2b3c4d rootName=BG5ESN issuerSn=1001 issuerFp=7f8e9d0c issuerName=bd4wpw payloadLen=3120 payloadSha256=3f2a9c1d4b5e6f70 passwordLen=4160 req=0f9e8d7c6b5a reason="timestamp expired"
```

`rootFp` / `issuerFp` are the first 8 hex characters of the certificate fingerprint, used to distinguish CAs that share the same SN.

Entry-point protections:

- `username` is limited to 32 UTF-8 bytes and only `A-Z 0-9 / -`; invalid requests are denied before any parsing or archiving.
- Global rate limit defaults to 600 requests/minute.
- A callsign with 20 failures within 5 minutes is temporarily blocked for 10 minutes. Only failures after the certificate chain has been verified count, so an attacker cannot lock out a victim by spoofing their callsign.
- `http.maxPasswordBytes` rejects oversized password fields.
- Untrusted values are escaped before being written to the plain-text log.

Records are grouped by callsign and day, one JSON object per line:

```text
~/.sas/archive/
  BG6VMZ/
    2026-11-18.jsonl
  BD4WPW/
    2026-11-18.jsonl
```

Directory names use the uppercase callsign with `/` replaced by `_` (for example `BG6VMZ/P` → `BG6VMZ_P`). The valid callsign alphabet excludes `_`, so this mapping cannot collide; the record's `callsign` field always keeps the original value.

```json
{
  "v": 1,
  "ts": "2026-11-18T20:34:56.789+08:00",
  "requestId": "a1b2c3d4e5f6",
  "callsign": "BG6VMZ",
  "result": "allow",
  "reason": null,
  "rootSn": 1,
  "rootFp": "1a2b3c4d5e6f7890a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e",
  "rootName": "BG5ESN",
  "issuerSn": 1001,
  "issuerFp": "7f8e9d0c1b2a34560f1e2d3c4b5a69788697a8b9c0d1e2f30415263748596071",
  "issuerName": "bd4wpw",
  "userUid": 50001,
  "role": "user",
  "claimedRole": "user",
  "targetCallsign": "BG5ESN",
  "targetUid": 5001,
  "targetUrl": "fmo.example.com",
  "targetPort": 1883,
  "timestamp": 1783291399,
  "passwordLength": 4160,
  "passwordSha256": "9c1d4b5e6f70a1b2",
  "payloadLength": 3120,
  "payloadSha256": "3f2a9c1d4b5e6f70",
  "password": "eyJjZXJ0UGFja2FnZSI6...",
  "payload": { "certPackage": { "...": "complete original payload" } }
}
```

- Successful logins store the full `password` and `payload`.
- Failed logins store a summary by default: `password` and `payload` are `null`, while lengths, `passwordSha256`, `payloadSha256`, failure reason, and certificate chain details are kept. Set `archive.recordDeniedPayload=true` or use `archive.deniedPayloadSampleRate` to keep full failed payloads.
- Malformed requests that cannot be decoded are only logged, not archived.
- SAS does not record the source IP. To locate a device's real IP, use the EMQX client list or connection logs.
- On Linux the archive directory is created as `0700` and files as `0600`. Payloads contain no private keys, but do contain the full certificate chain and signatures — do not share them publicly.
- `archive.retentionDays` controls retention; `archive.maxFileBytes` is the target file-size cap (overflow goes to `.1`, `.2`, ...; a single record is never split, so a file may exceed the cap by one record); `archive.maxRecordBytes` caps each record and degrades it to a summary, a trimmed summary, or a core-fields record while always emitting valid JSON.
- In Docker the archive lives in the `sas-data` volume. Set `TZ` if you want files split by local date (Compose defaults to `Asia/Shanghai`).

Inspect recent records:

```bash
tail -n 20 ~/.sas/archive/BG6VMZ/2026-11-18.jsonl | jq .
```

### Admin Management

SAS provides interactive admin management commands to configure additional admin privileges:

```bash
# Add admin (interactive)
sas --add-admin [--config <path>]

# Remove admin (interactive)
sas --remove-admin [--config <path>]

# List current admins
sas --list-admins [--config <path>]
```

- The **super role** requires both the server's own UID and certificate fingerprint (`user.uid == server.uid` and the cert fingerprint equals `server.certFingerprint`) — no manual configuration needed
- The admin list only stores regular admins (admin role), stored in the `Server.admins` array in `config.json`; entries match on UID + certificate fingerprint
- Use `--config <path>` to specify a non-default config file location

For Docker Compose deployments, manage administrators interactively in the running SAS container:

```bash
docker exec -it fmo-sas dotnet sas.dll --add-admin
docker exec -it fmo-sas dotnet sas.dll --remove-admin
docker exec -it fmo-sas dotnet sas.dll --list-admins
```

### Cluster Management

If you have multiple MQTT Brokers sharing a single SAS instance, you can add cluster nodes:

```bash
# Add cluster node (interactive)
sas --add-cluster [--config <path>]

# Remove cluster node (interactive)
sas --remove-cluster [--config <path>]

# List current cluster nodes
sas --list-clusters [--config <path>]
```

- Cluster node information is stored in the `Mqtt.clusters` array in `config.json`
- Once added, devices connecting to these Brokers can also authenticate through this SAS
- The cluster node's UID plus matching certificate fingerprint grants the super role on that node

For Docker Compose deployments, register an independent FMO service through the shared SAS configuration volume:

```bash
# Enter the external FMO service UID, callsign, MQTT host, port, and certificate fingerprint when prompted
docker exec -it fmo-sas dotnet sas.dll --add-cluster

# List or remove registered external services
docker exec -it fmo-sas dotnet sas.dll --list-clusters
docker exec -it fmo-sas dotnet sas.dll --remove-cluster

# Reload the updated configuration in the long-running SAS process
docker compose restart sas
```

Set the external service's MQTT Host to a hostname or IP address reachable by devices, not to a service name on this Compose network.

### Startup Address Display

When `http.addr` is set to `0.0.0.0`, SAS lists all available IPv4 addresses with their corresponding auth endpoint URLs at startup, making it easy to identify the access address.

---

## OTA Auto-Update

SAS has built-in version checking and auto-update:

```bash
# Manually check and update to the latest version
sas --update
```

- **Auto-check**: Automatically checks for new versions on startup, prompts upgrade command when available
- **Disable auto-check**: Set `"update": { "enabled": false }` in `config.json`
- **Docker environment**: Automatically detects Docker runtime, suggests `docker pull` update method

---

## Testing

The `test-case/` directory contains integration test tools and scripts:

| Tool/Script | Purpose |
|-------------|---------|
| `FingerprintTool/` | Certificate fingerprint calculation tool |
| `HttpChecker/` | HTTP auth request simulator |
| `run-test.ps1` | Positive tests (valid cert passes auth) |
| `run-test-negative.ps1` | Negative tests (invalid/expired certs rejected) |
| `run-user-sim.ps1` | User simulation test |
| `send-auth.ps1` | Send single auth request |

Run tests:

```powershell
cd test-case
./run-test.ps1
./run-test-negative.ps1
```

---

## Directory Structure

```
fmo-server-authorizer-service/
├── src/                            ← Source code
│   ├── Sas.csproj                  ← Project file (.NET 10.0)
│   ├── Program.cs                  ← Entry: CLI parsing + interactive config + startup
│   ├── Server/                     ← HTTP listener and rate limiting
│   │   ├── HttpServer.cs           ← /auth endpoint
│   │   └── AuthRateLimiter.cs      ← Global rate limit + callsign breaker
│   ├── Messages/                   ← HTTP auth payload DTOs
│   ├── Trust/                      ← Certificate verification + CRL management
│   │   ├── RootCaStore.cs          ← Root CA loading
│   │   ├── CertVerifier.cs         ← Certificate chain verification
│   │   └── CrlManager.cs           ← CRL download/cache/revocation check
│   ├── Auth/                       ← Auth processing + ACL
│   │   ├── HttpAuthHandler.cs      ← Core auth logic
│   │   ├── AuthRequestContext.cs   ← Request context (request ID / archive fields)
│   │   ├── CallsignValidator.cs    ← Callsign format and length validation
│   │   ├── HttpProofVerifier.cs    ← Ed25519 signature verification
│   │   ├── AclStore.cs             ← Role permissions (super/admin/user)
│   │   └── EmqxResponseTemplate.cs ← EMQX response format
│   ├── certs/                      ← Cert data structures + Ed25519 + Base64Url
│   ├── Logging/                    ← Logging and login archive
│   │   ├── Logger.cs               ← Console logging
│   │   ├── LogSafe.cs              ← Log field escaping
│   │   └── AuthArchive.cs          ← Per-callsign login payload archive
│   └── builtin/                    ← Built-in data
│       ├── roots/bg5esn.json       ← Built-in Root CA
│       └── roles/                  ← Role permission definitions (super/admin/user)
├── scripts/
│   ├── publish.ps1                 ← Multi-platform build & package
│   ├── install.sh                  ← Linux/macOS install script
│   └── install.ps1                 ← Windows install script
├── config/
│   └── config.example.json         ← Example configuration
├── test-case/                      ← Integration tests
├── docs/                           ← Detailed documentation
├── Sas.sln                         ← Visual Studio solution
└── README.md
```

### Runtime Directory

```
~/.sas/
├── config.json            ← Configuration (single source of truth)
├── roots/                 ← Root CA certificates
│   └── bg5esn.json
├── roles/                 ← Role permission definitions
│   ├── super.json
│   ├── admin.json
│   └── user.json
├── crl/                   ← CRL cache (keyed by certificate fingerprint, auto-refreshed)
│   ├── root-BG5ESN-1a2b3c4d5e6f7890/
│   │   ├── root.json
│   │   └── meta.json
│   └── intermediate-bd4wpw-7f8e9d0c1b2a3456/
│       ├── intermediate.json
│       └── meta.json
└── archive/               ← Login payload archive (per callsign/day)
    └── BG6VMZ/
        └── 2026-11-18.jsonl
```

CRL cache directories are keyed by certificate fingerprint (`{type}-{safeName}-{fp16}`). Legacy `crl/{sn}/` caches are ignored and fetched again. With `crl.mode=strict`, authentication is denied from startup until the first CRL fetch succeeds; watch for `Root CRL updated` in the log, or start in `soft` mode to warm the cache before switching to `strict`.

`fp16` is the first 16 hex characters (64 bits) of the SHA-256 fingerprint and only keeps directory names readable alongside `safeName`. Real deployments have very few CAs, so collisions can be ignored; even if two directories collide, every CRL is still verified with `VerifyBy` before use, so a mismatched cache is never trusted and one CA's revocation state cannot leak into another.

Intermediate certificates only appear in login payloads, so `CrlManager` cannot know or prefetch all Intermediate CRLs at startup. In `soft` mode, the first request that introduces an Intermediate with no local cache is allowed while the CRL is fetched in the background; later requests hit the cache. Use `crl.mode=strict`, or pre-populate the cache directory, when revocation must be enforced from the very first request.

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Exits immediately after start | Run `sas --help` to verify arguments; check for missing required fields |
| `Roots directory not found` | Root CA not installed, verify built-in certs exist |
| `Root CA self-signature failed` | Certificate file corrupted, re-obtain |
| `curl` returns empty or connection refused | Check if port 8080 is blocked by firewall |
| CRL refresh 404 | Normal in `soft` mode; in `strict` mode authentication is denied until the CRL is published and fetched |
| Auth always returns deny | Check certificate chain completeness, expiration, or revocation; use the log `req` ID to find the full payload in the archive |
| Archive directory is empty | Check `archive.enabled`; only requests whose password JSON can be decoded are archived |

---

## Important Notes

1. **No Sensitive Data**: All fields in `config.json` are public information (callsigns, certificate fingerprints, network addresses, etc.) — no private keys or passwords are stored. Security is guaranteed by the device-side private key.
2. **Internal Deployment**: HTTP endpoint should listen on `127.0.0.1` or internal addresses, never exposed directly to the public internet.
3. **Source of Truth**: After initial setup, modify configuration by editing `config.json` (restart to apply), or re-launch with CLI arguments to auto-update the config.
4. **Upgrades**: `sas --update` automatically downloads the latest version and restarts (disable: `update.enabled = false`).
5. **Device Side**: FMO device firmware must use SAS HTTP authenticator mode (carrying certificate info in username/password during MQTT CONNECT).
6. **Login Archive**: Successful logins store full payloads; failed logins store summaries by default. Archive files contain the certificate chain and proof signatures (no private keys) and are intended for auditing and troubleshooting. Restrict access to the archive directory and tune `archive.retentionDays`, `archive.maxFileBytes`, and `archive.maxRecordBytes` as needed.
7. **Entry Protection**: `username` is limited to 32 UTF-8 bytes and callsign characters only. The default global rate limit is 600 requests/minute. A callsign breaker only counts failures after certificate chain verification, so early spoofed failures cannot lock out legitimate users. Tune these in `http.rateLimit`.

---

## Documentation

- [SAS HTTP Authentication](docs/V4.0%20SAS%20HTTP%20Authentication.md)
- [SAS Development Guide](docs/V4.0%20SAS.NET%20Development.md)
- [SAS OTA Update](docs/V4.0%20SAS%20OTA%20Update.md)
- [V4 Signatures & Certificates Protocol](docs/V4.0%20Protocol%20-%20Signatures%20%26%20Certificates.md)
- [V4 Root CRL Format](docs/V4.0%20Protocol%20Root%20CRL%20Formate.md)
- [V4 Intermediate CRL Format](docs/V4.0%20Protocol%20Intermediate%20CRL%20Formate.md)

---

## License

This project is licensed under the [GPL-3.0](LICENSE) License.
