# antlion [WIP]

![antlion logo](https://github.com/Smiduweorc/antlion/blob/master/assets/logo.png?raw=true)

**Antlion makes DPoP mistakes impossible by construction. It is for resource servers that already verify access tokens with [Lacewing](https://github.com/Smiduweorc/lacewing) and now need those tokens bound to a key: one call checks the access token, the proof and the key binding together, or rejects the request.**

It implements the resource-server side of [RFC 9449 (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449), with the algorithm set from the FAPI 2.0 Security Profile. A token stolen off the wire, out of a log, or from a proxy is useless to anyone who does not also hold the client's private key. It does not create proofs, run an authorization server, or read client certificates.

Lacewing is a peer dependency, and the access token is still verified by a Lacewing profile. [jose](https://github.com/panva/jose) is the one direct dependency, used only for the proof. Nothing happens at import time.

> **Status:** not released. This project is still a work in progress and most of my commits are in my gitlabs server.

## Antlion is not for you if you

- **want to create DPoP proofs.** That is the client's side. [oauth4webapi](https://github.com/panva/oauth4webapi) and [openid-client](https://github.com/panva/openid-client) already do it well, including the retry on a nonce challenge.
- **run an authorization server.** Issuing `cnf.jkt` tokens, `dpop_jkt`, PAR and PKCE belong to [oidc-provider](https://github.com/panva/node-oidc-provider), Keycloak, and the rest of that shelf.
- **want one endpoint to accept `Bearer` and `DPoP` while you migrate.** An endpoint that accepts both is exactly as strong as `Bearer`. Route the two kinds of traffic to two profiles, on purpose, and delete the old route when you are done.
- **bind tokens with mTLS.** RFC 8705 works at the TLS layer and needs the client certificate to reach your service. Nothing here reads a certificate.
- **use opaque tokens and introspection.** v1 is JWT access tokens (RFC 9068) only, where `cnf.jkt` travels inside the token.
- **want it to work out your URL from the request.** `origin` is required. `Host`, `X-Forwarded-*` and `Forwarded` are never read, because they are whatever the client or the nearest proxy says they are.
- **want replay protection without state.** A proof is single-use, so something has to remember which ones it has seen. The replay store is required by the type, and there is no safe DPoP verifier that is stateless.
- **are not using Lacewing.** Antlion wraps a Lacewing profile and adds nothing to what that profile checks. Without Lacewing, `oauth4webapi`'s `validateJwtAccessToken` does the binding correctly; [With panva's tools](./guides/panva.md) lists what to add around it.

## How it works

The access token, the proof and the binding between them are one check. There is no function that verifies a proof on its own, because a valid proof only shows that *someone* holds *some* key. The security is in tying that key to the token and the proof to this request, so a result only exists once all of it has passed.

In outline, `verifyDPoPRequest(request, profile)` does this, in this order, and stops at the first refusal:

```text
one  Authorization: DPoP <token>   (Bearer refused, duplicates refused)
one  DPoP: <proof>                 (duplicates refused)

proof:     size, shape, typ is dpop+jwt, alg on the allowlist and matching the key
request:   htm == method, htu == configured origin + normalised path
proof:     signature, against the public key in its own header
token:     your Lacewing profile, unchanged
binding:   thumbprint(proof key) == token.cnf.jkt
           proof.ath == sha256(token)
freshness: iat inside a capped window, server nonce if you turned nonces on
replay:    first time this proof has been seen, or refuse

-> DPoPVerifiedJwt
```

What follows from that:

- **There is one way to verify.** No proof-only verifier is exported, so "checked the proof, forgot the binding" is not something you can write.
- **Cheap checks run before expensive ones, and the store runs last.** Nothing unauthenticated reaches the replay store, so garbage can't be used to fill it or probe it.
- **The key in a proof header is trusted for the proof and nowhere else.** Verifying against an embedded key happens in exactly one internal module, and the access token never goes near it.
- **The algorithms are the FAPI 2.0 set:** `PS256`, `ES256`, and Ed25519 under either `EdDSA` or its fully-specified RFC 9864 name `Ed25519`, which is what panva's clients send. `none` and HMAC can't be expressed. `RS256` exists only behind an explicit legacy import, the same way Lacewing does it.
- **Antlion writes the refusal.** A 401 with a spec-correct `WWW-Authenticate: DPoP` and, when nonces are on, a `DPoP-Nonce`. The caller sees `invalid_token` or `invalid_dpop_proof` and nothing more; the precise reason comes back to you as a typed code for your own logs.

## What you decide

A DPoP profile wraps the Lacewing profile you already have. Four things have no default, because only you know the answer:

```text
dpopProfile:
  token:   your Lacewing access-token profile (at+jwt)
  origin:  "https://api.example.com"
  replay:  a store with one atomic addIfAbsent(key, ttl)
  nonce:   "required" | "off"
```

- **The origin** is the one your clients sign against. `htu` is compared to it exactly, after RFC 3986 normalisation, with the query and fragment removed.
- **The replay store** holds each proof's `jti` for as long as a proof could still be fresh. The in-memory store is for one process and for tests, and its name says so. Across a fleet, the store is `SET NX PX` in Redis or `INSERT ... ON CONFLICT DO NOTHING` in Postgres. If the store errors, the request is refused.
- **Nonces** are a trade. `"required"` costs an extra round trip whenever a client needs a fresh nonce, and stops proofs being generated ahead of time with a lying clock. `"off"` trusts the client's `iat`. When they are on, nonces are stateless (an HMAC over a time window), so every node accepts the same ones and the secret can be rotated.

## What DPoP does, and what it does not

People expect more from DPoP than it gives, and then expect it from Antlion.

- **It stops replay, not theft.** A leaked token is useless without the key. Malware or an XSS running inside the client can still use the key to sign fresh proofs, and nothing on the server can tell. Antlion makes leaked tokens worthless; it can't protect a compromised client.
- **It hides nothing.** The token is as readable as it was before. If the payload is a secret, that is Lacewing's JWE support.
- **It isn't stateless.** Replay protection needs a store, and nonces need either shared state or a shared secret.
- **`iat` alone is not freshness.** It is the client's clock, so a proof can be signed today for use tomorrow. Server nonces close that.
- **It is not interchangeable with mTLS.** FAPI accepts both, but they fit different infrastructure. DPoP lives in the application layer and survives TLS being terminated at a proxy; mTLS needs the certificate to reach you.

## Documentation

| Guide | What it covers |
| --- | --- |
| [Boundaries](./guides/boundaries.md) | What Antlion owns, what it will never do, and where that work goes |
| [With panva's tools](./guides/panva.md) | `oidc-provider` and `openid-client` around Antlion, what has to match, and when to use `oauth4webapi` instead |

## Where it sits

| Package | Question it answers |
| --- | --- |
| [Lacewing](https://github.com/Smiduweorc/lacewing) | Is this token signed by who it claims, unexpired, and meant for me? |
| **Antlion** | **Is the one presenting it the one it was issued to, and is this request the one they signed?** |

A whole FAPI 2.0 setup with DPoP, in one line:

```text
Lacewing + Antlion  +  oidc-provider         +  openid-client
(your API)             (authorization server)   (the client)
```

Antlion reads the headers, verifies the proof, hands the token to your Lacewing profile, then checks that the two belong together. [oidc-provider](https://github.com/panva/node-oidc-provider), or Keycloak, Curity or whatever else you run, puts `cnf.jkt` in the token. [openid-client](https://github.com/panva/openid-client), built on [oauth4webapi](https://github.com/panva/oauth4webapi), holds the key and signs a proof for every request. Antlion is only the first part. Past one node, add a shared replay store (Redis or Postgres). [With panva's tools](./guides/panva.md) covers what the three have to agree on.

## Known quirks

- **It needs a Lacewing that doesn't exist yet.** Antlion shares Lacewing's algorithm registry, header reading and duration parsing through a small, versioned `lacewing/extension` export, so the two can't drift apart. That export has to ship in Lacewing first, and Lacewing's registry needs an `Ed25519` entry next to `EdDSA`.
- **JWT access tokens only.** Opaque tokens and introspection are out of v1, and may stay out.
- **Browsers need CORS.** A browser client has to be allowed to send `DPoP` and to read `DPoP-Nonce`. Antlion exports the header names; the CORS policy is yours.
- **No benchmarks yet.** There is no public harness, so there is no performance claim.

## Why Antlion exists

Lacewing's README says proof-of-possession is beyond its bearer-token scope, and it meant it. Then a Lacewing user needed FAPI 2.0, which requires tokens bound to the client, and DPoP is the binding that works behind a TLS-terminating proxy. So the insect grew a sibling.

The JavaScript resource-server side is thin. panva's oauth4webapi does validate DPoP-bound access tokens, and it is excellent, but it is a general OAuth client with its own settings. Putting it under Lacewing would mean two policy layers that can disagree about what "valid" means, and the disagreement would be where the bug lives.

DPoP is a short spec with a lot of room to get it quietly wrong, and every one of these passes a test suite that only ever sends valid requests:

- Verifying the proof and the token, and never comparing `cnf.jkt`
- Accepting a DPoP-bound token under the `Bearer` scheme
- Accepting a token with no `cnf.jkt` under the `DPoP` scheme
- Verifying the access token against the key in the proof header
- Comparing `htu` by prefix, or against a URL rebuilt from `X-Forwarded-Host`
- Treating `ath` as optional
- Tracking `jti` in memory on each of twenty nodes, or failing open when the store is down
- Letting the header pick the algorithm

Each of those is either impossible to express in Antlion or enforced on every request.

## Scripts

| Script | What it does |
| --- | --- |
| `npm run build` | Compile `src/` and `index.ts` to `dist/` with type declarations. |
| `npm run typecheck` | Type-check the package and the tests without emitting. |
| `npm run lint` | Run ESLint. |
| `npm run lint:fix` | Run ESLint and fix what it can. |
| `npm test` | Run the test suite with the Node test runner via `tsx`. |
| `npm run docs` | Generate the API reference into `docs/` with TypeDoc. |
| `npm run changelog` | Regenerate `CHANGELOG.md` from the commit history. |

> Publishing and deployment are handled manually (custom npm settings), so no release/publish workflow is included here.

## Lore

Antlions and lacewings are both Neuroptera, and a grown antlion is easy to mistake for a lacewing. It isn't one, and it doesn't replace one.

The larva is the famous part. Some species dig a cone in loose sand at exactly the steepest angle the sand will hold, and sit at the bottom. An ant that steps over the rim finds that every step it takes brings the slope down with it. The antlion doesn't chase anything; the shape of the pit does the work. That is the whole design brief.
