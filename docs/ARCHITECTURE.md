# Architecture

Three roles, one encrypted channel. Both ends dial **out** to the relay, so nothing needs an inbound port.

```
A side (controller)                     relay (blind)                      B side (target)
┌───────────────────────────┐     ┌────────────────────────┐     ┌──────────────────────────┐
│ opencode / OpenChamber    │     │        ocwire-hub      │     │  ocwire-desktop (Wails)  │
│  ├─ plugin/client.mjs     │     │  TLS 1.3 (pinned fp)   │     │   or oclink-agent (CLI)  │
│  │   ├─ connection manager│◄───►│  sessions map          │◄───►│  agent runtime           │
│  │   └─ E2EE session      │ E2EE│  store: deviceId+subkeys│E2EE │  ├─ exec / files / grep  │
│  ├─ plugin/oc-link.ts     │     │  admin console + audit │     │  ├─ service + autostart  │
│  └─ OpenChamber panel     │     │  releases (signed)     │     │  └─ self-register        │
└───────────────────────────┘     └────────────────────────┘     └──────────────────────────┘
```

## Key schedule (HKDF-SHA256, per purpose)

```
deviceKey ──HKDF("ocl-link:auth")────────► authKey (device)      → stored on relay
          ──HKDF("ocl-link:e2ee")────────► encKey (device/target) → never leaves endpoints
          ──HKDF("ocl-link:client:<cid>")► clientKey (per controller)
                                          └─HKDF("ocl-link:auth")→ client authKey → stored on relay
```

- `deviceId = SHA-256("ocl-link:device:" + deviceKey)[:8]` — public, non-reversible.
- Relay auth: HMAC challenge-response over `nonce|role|deviceId|clientId`; keys never transmitted.
- Session: X25519 ECDH mixed with `encKey`, AES-256-GCM, `seq` as AAD (replay/reorder protection).

## Message flow

1. **Self-register** — B generates `deviceKey`, sends `deviceId + authKey` to the relay with `register`.
2. **Pair** — B issues an `OCL2:` invite (hub/fingerprint/deviceId/clientId + per-controller `clientKey`, base64url JSON) as QR or text.
3. **Connect** — A stores the invite as a target; its connection manager dials the relay, completes the HMAC handshake, then the E2EE handshake with B. Requests are JSON (`exec/read/write/...`), responses stream back over the sealed channel.
4. **Presence** — when A is not controlling, its engine keeps a lightweight `presence:true` connection so the console can tell "A online (standby)" from "A offline". Presence does not disturb B.
5. **Admin** — the hub console lists online devices/controllers, supports kick / disable / enable / cooldown / delete-offline, and serves the signed release manifest for agent auto-update.

## Components

| Path | Role |
|---|---|
| `internal/hub` | relay: TLS listener, sessions, store (`devices.json`), audit (JSONL, 3-day trim), admin API + page, release server |
| `internal/agent` | B runtime: connect/reconnect, service mode, self-register, signed auto-update |
| `internal/proto` | envelopes + HKDF key schedule + E2EE session |
| `internal/wire` | 4-byte length framing (32 MB cap) |
| `internal/client` | protocol client used by CLI tests (`cmd/octest`) |
| `plugin/` | A engine (manager) + opencode tools |
| `extension/` | OpenChamber panel: devices / add / logs (host service proxy) |
| `desktop/` | Wails GUI: B features + A page, onboarding, logs, settings |
| `cmd/{hub,agent,relsign,octest}` | binaries |

## Deployment

- Relay: a small VPS. `oclink-hub -tunnel :21122 -admin :10000 -data <dir>`; TLS cert auto-generated, its fingerprint is what other sides pin. Admin console password is printed on first boot (or set with `-admin-password`).
- B: run the desktop app (auto-registers, auto-starts with the OS if enabled) or install the CLI agent as a service (`oclink-agent install`).
- A: copy the two plugin files into `~/.config/opencode/plugins/`, restart the shell, add targets by invite code. The connection manager persists inside the opencode process; the OpenChamber panel and the desktop A page are just views onto it.
- Updates: `relsign` signs `release.json` (Ed25519); agents verify signature + SHA-256 before applying. Never publish a release manifest signed by a leaked key — keep `release.key` offline.
