---
title: With panva's tools
---

# With panva's tools

Checked against `oauth4webapi` 3.8.8, `openid-client` 6.8.8 and
`oidc-provider` 9.12.2 in September 2026. Option names move between majors,
so check your versions before copying one.

| Role | Job | Package |
| --- | --- | --- |
| Authorization server | Log the user in, issue an `at+jwt` with `cnf.jkt`, handle PAR and PKCE | `oidc-provider` |
| Client | Hold the key, sign a proof per request, answer a nonce challenge | `openid-client` (or `oauth4webapi` underneath it) |
| Resource server | Check the token, the proof, and that they belong together | Lacewing + Antlion |

## The authorization server: `oidc-provider`

- Turn on `features.dPoP`, and `features.fapi` with `profile: "2.0"`. The
  FAPI profile brings PAR and PKCE with it.
- Ask for JWT access tokens. `oidc-provider` issues opaque tokens unless
  `features.resourceIndicators.getResourceServerInfo` returns
  `accessTokenFormat: "jwt"` for your API, and Antlion only reads JWTs. The
  default `getResourceServerInfo` throws until you write one.
- `enabledJWA.dPoPSigningAlgValues` defaults to `ES256`, `Ed25519` and
  `EdDSA`. Add `PS256` if your clients use RSA keys, and nothing else.
- `features.dPoP.nonceSecret` and `requireNonce` govern the token endpoint
  only. Your API's nonces use a separate secret, and clients handle the two
  independently.

## The client: `openid-client`

```text
keyPair = generateKeyPair("ES256")            non-extractable by default
dpop    = getDPoPHandle(config, keyPair)

token   = authorization code grant, with DPoP: dpop
data    = fetchProtectedResource(config, token, url, method, ..., { DPoP: dpop })
```

- Use one key and one handle for the session. The same handle signs the
  token request and every API call. A new key breaks the tokens bound to the
  old one.
- `fetchProtectedResource` retries once when your API answers
  `use_dpop_nonce`, so turning nonces on costs the client a round trip and
  no code.
- Ed25519 proofs say `Ed25519`, not `EdDSA`: `oauth4webapi` writes the RFC
  9864 name. Antlion accepts both names for an Ed25519 key.
- The `url` the client fetches is the `htu` it signs. Your `origin` plus the
  path has to produce the same string.

## The resource server: Lacewing + Antlion

```text
accessToken = Lacewing access-token profile
  issuer:     the oidc-provider issuer
  audience:   the resource indicator the client asked for
  keys:       the issuer's jwks_uri, with your cache TTL, cooldown and timeout
  algorithms: the ones the issuer signs access tokens with

dpop = Antlion profile
  token:  accessToken
  origin: the public origin clients call, as a URL parser prints it
  replay: a shared store once there is more than one node
  nonce:  "required" (with nonceSecrets) | "off"
```

The proof algorithms are Antlion's FAPI set and are not configured.

## Where the three have to agree

| Thing | Set in | Must match |
| --- | --- | --- |
| Token format | `getResourceServerInfo` | `"jwt"`, or Antlion refuses every token |
| Audience | the resource indicator | Lacewing's `audience` |
| Proof algorithms | `dPoPSigningAlgValues` and the client's key | `PS256`, `ES256`, Ed25519 as `EdDSA` or `Ed25519` |
| `htu` | the `url` the client fetches | Antlion's `origin` plus the path |
| Nonces | each server separately | nothing; they are independent |

## When to use `oauth4webapi` instead

`oauth4webapi`'s `validateJwtAccessToken` does the binding correctly:
`cnf.jkt` is compared against the proof key's thumbprint, `ath` is
required, `htm` is exact, and a bound token under `Bearer` is refused. If
you are not on Lacewing, use it and skip Antlion.

Where the two differ, as of 3.8.8:

| Behaviour | `validateJwtAccessToken` | Antlion |
| --- | --- | --- |
| A `Bearer` token with no `cnf` | accepted, unless `requireDPoP: true` | refused |
| Proof `jti` replay | checked to be a string, not recorded | recorded once in a store you supply |
| Server nonces | not checked; the docs say to check them afterwards | checked, when on |
| `htu` compared against | `request.url` | the configured `origin` plus the path |
| Proof age | 300 seconds either side of now, fixed | a window you size, under a cap |
| Default proof algorithms | includes `RS256`/`384`/`512` and ML-DSA | the FAPI set only |
| Access token verified by | its own validator, from the issuer's metadata | your Lacewing profile |

Each left-hand row can be closed from outside: `requireDPoP: true`, a
`signingAlgorithms` list, a `jti` store and a nonce check after the call,
and a `Request` whose `url` you built from your public origin rather than
the `Host` header.

Don't run both on the same route. When they disagree about a request you
end up debugging the difference between them.
