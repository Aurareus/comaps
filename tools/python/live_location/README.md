# Live location (NLL v1) tools

Python reference implementation and test tooling for the live location sharing protocol specified in
[`docs/LIVE_LOCATION_PROTOCOL.md`](../../../docs/LIVE_LOCATION_PROTOCOL.md). The design rationale is in
[`docs/LIVE_LOCATION.md`](../../../docs/LIVE_LOCATION.md).

The reference implementation is deliberately built on different libraries from the C++ one, so that
the two can be checked against each other:

- PyCA `cryptography` (OpenSSL) for ChaCha20, ChaCha20-Poly1305 and X25519;
- `coincurve` (libsecp256k1) for BIP-340;
- the standard library for SHA-256 and HMAC.

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

## Contents

| File | Purpose |
|---|---|
| `nll/` | Reference implementation: `primitives`, `nip44`, `noise` (NNpsk0), `nostr` (NIP-01 events), `protocol` (NLL v1) |
| `test_primitives.py` | Checks the primitives against the published RFC 5869, NIP-44 v2, BIP-340 and Noise (cacophony) vectors |
| `test_protocol.py` | Scenario tests: pairing, man-in-the-middle with a leaked invite, sharing, revocation, epochs, signals, tampering, replay |
| `make_vectors.py` | Regenerates `vectors/nll1_vectors.json` deterministically |
| `vectors/` | NLL v1 test vectors; `external/` holds the third-party vectors (see `external/SOURCES.md`) |
| `relay_probe.py` | Feature probe of public relays: kinds from fresh keys, replacement, NIP-40, NIP-09, ephemeral forwarding, bursts |
| `relay_probe_sustained.py` | Author-list caps, NIP-40 purge lag, 1-event-per-5-s cadence with latency, idle connections |
| `relay_soak.py` | Long soak test with reconnects: refusals, disconnects, missed live deliveries, latency percentiles |
| `probe_summary.py` | Compact table from `relay_probe.py` output |
| `results/` | Raw results of the relay tests reported in the design document |

## Running

```bash
.venv/bin/python -I test_primitives.py      # downloads the NIP-44 vectors once, checksum-verified
.venv/bin/python -I test_protocol.py
.venv/bin/python -I make_vectors.py         # must not change vectors/nll1_vectors.json unless the spec changed
.venv/bin/python -I relay_probe.py out.json wss://nos.lol wss://nostr.mom
.venv/bin/python -I relay_soak.py out.json 1800 wss://nos.lol wss://nostr.mom wss://relay.primal.net
```

The relay scripts use fresh random keys for every test, and never use AUTH, proof of work or
payment. They publish a small volume of random ciphertext-shaped events that expire within 15
minutes. The NIP-09 check also publishes one deletion request per relay. Relays keep those
indefinitely, so since 2026-10-09 it carries a 10-minute expiry. The first runs (results of
2026-10-09) left about 15 such random-key deletion requests without one.
