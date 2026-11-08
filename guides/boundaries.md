---
title: Boundaries
---

# Boundaries

Lacewing checks the token: signed by the issuer, unexpired, meant for this
API. Antlion checks that whoever sent it holds the key it is bound to, and
that the proof was made for this request. Your Lacewing profile is passed in
unchanged; Antlion adds refusals and removes none.

## What Antlion checks

- The headers. Exactly one `Authorization: DPoP` and exactly one `DPoP`. A
  second copy of either is refused, and so is the `Bearer` scheme. Two
  headers joined by `Headers` into one value are caught, because a compact
  JWS never contains a comma.
- The proof. `typ` is `dpop+jwt`, `alg` is on the allowlist and matches the
  key's type and curve, and a key with private members is refused. The
  signature is checked against the key in the proof header, which is the
  only place in the package that key is used.
- The request. `htm` equals the method. `htu` equals the configured origin
  plus the request path, normalised per RFC 3986, without query or
  fragment. `ath` is the SHA-256 of the token string presented, and is
  always required.
- The binding. The RFC 7638 thumbprint of the proof key, computed by `jose`
  and never read from input, equals the token's `cnf.jkt`. A token with no
  `cnf.jkt` is refused.
- Freshness and replay. See [Deployment](./deployment.md) for the window,
  nonces and the stores.

## What it leaves to something else

| Not in Antlion | Where it goes |
| --- | --- |
| Verifying the access token | Your Lacewing profile |
| Creating proofs, retrying on a nonce challenge | oauth4webapi or openid-client |
| Issuing bound tokens, `dpop_jkt`, PAR, PKCE, binding refresh tokens | The authorization server (oidc-provider, Keycloak, Curity) |
| `Bearer` on a DPoP route | A second route with a plain Lacewing profile |
| Working out the request URL | The `origin` option; `Host` and `X-Forwarded-*` are never read |
| The Redis or Postgres connection | Your client (`ioredis`, `node-redis`, `pg`), passed to the store |
| Creating the Postgres table, deleting expired rows | Your migrations and your scheduler, calling `deleteExpired()` |
| Keeping replay keys through a failover | Postgres with synchronous replication; Redis can't |
| mTLS (RFC 8705) | Not supported |
| Opaque tokens and introspection | Not supported in v1 |
| A compromised client signing fresh proofs | The client: non-extractable WebCrypto keys, a CSP |
| Rate-limiting bad proofs | Your edge or gateway |

Antlion also does no logging, reads no `process.env`, does no work at import
time and uses no `node:` imports. Hashing uses `globalThis.crypto`.
