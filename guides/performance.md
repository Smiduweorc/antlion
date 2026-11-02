---
title: Performance
---

# Performance

**What one verification costs, measured by a harness you can re-run (`npm run bench`, or the Bench workflow on a GitHub runner).**

`npm run bench` times `verifyDPoPRequest` one request at a time, on one core, with `SingleProcessReplayStore`. Proofs are signed beforehand, so what is timed is verifying the proof, the ES256 access token through Lacewing 3, the binding, and the store write. On Node 26.13, Linux, an Intel Core 7 350:

| Request | Per second | p50 | p99 |
| --- | ---: | ---: | ---: |
| accepted, ES256 proof | 2,909 | 0.309 ms | 0.667 ms |
| accepted, Ed25519 proof | 3,228 | 0.296 ms | 0.605 ms |
| accepted, PS256 proof | 3,484 | 0.265 ms | 0.561 ms |
| accepted, ES256 proof, nonces on | 2,715 | 0.344 ms | 0.667 ms |
| refused: Bearer scheme | 67,082 | 0.011 ms | 0.038 ms |
| refused: htu mismatch, before any signature | 46,329 | 0.019 ms | 0.037 ms |
| refused: bad proof signature | 5,691 | 0.154 ms | 0.417 ms |

A second run on this machine differed by up to 9% on accepted requests and by up to 27% on refusals, which finish in tens of microseconds and feel every scheduler hiccup. A request that fails before any signature costs about a sixteenth of one that verifies, which is the point of the fixed order. A shared store over the network adds its round trip to every accepted request, and nothing here measures that.
