# Security

ocwire moves commands and files between machines. Treat every component as sensitive infrastructure.

## Reporting a vulnerability

Open a private security advisory on GitHub, or email the maintainer. Please do not file public issues for exploitable bugs. Expect an initial reply within a few days.

## Design summary

- **End-to-end encryption.** Control sessions are AES-256-GCM with keys derived from an X25519 handshake mixed with a pairing key (`encKey`) that never leaves the two endpoints. The relay only forwards sealed frames.
- **Blind relay.** The hub stores a hashed `deviceId` and per-controller verification subkeys (`HKDF(pairingKey, "ocl-link:auth")`). It cannot derive `encKey` or any session key, and it never sees plaintext or file contents.
- **No inbound exposure.** Both A and B dial out to the relay. TLS 1.3 with a pinned SHA-256 certificate fingerprint; an unverifiable certificate aborts the connection.
- **Per-controller credentials.** Every controller gets an independent subkey derived from the device key (`HKDF(deviceKey, "client:"+clientId)`). Credentials can be disabled, kicked, or deleted without touching the others. Disabling is enforced at the relay on every handshake.
- **Replay protection.** Every message carries a monotonic `seq` authenticated as AAD; out-of-order or replayed frames are dropped. Handshake nonces are single-use.
- **Rate limits.** Relay-side registration limits (per IP), device caps, frame size caps (32 MB), and per-controller cooldowns after an admin kick.
- **Audit.** Relay keeps an append-only audit log (device/controller/time/duration, never key material), auto-trimmed to 3 days.
- **Signed updates.** Agent auto-update verifies an Ed25519 signature plus SHA-256 of the binary before applying.

## Operational guidance

- Give the relay its own host; keep the admin console on a private network or behind TLS.
- Keep the admin password out of unit files and shell history where possible.
- Rotate or disable a controller credential the moment a phone/laptop is lost; use "delete offline device" to purge uninstalled machines.
- Back up `data/devices.json` and `banned.json` (relay) if you care about the pairing list — they are not secrets, but losing them forces re-pairing.
