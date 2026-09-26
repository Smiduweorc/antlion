---
title: With panva's tools
---

# With panva's tools

**A DPoP deployment has three roles, and Antlion fills one of them. panva's
libraries fill the other two, and if you are not on Lacewing, one of them
fills the third as well.**

Everything here was checked against the published source of `oauth4webapi`
3.8.8, `openid-client` 6.8.8 and `oidc-provider` 9.12.2 in September 2026.
Option names move between majors, so check your versions before copying a
name out of this page.

## Who does what

```text
Lacewing + Antlion  +  oidc-provider         +  openid-client
(your API)             (authorization server)   (the client)
```

| Role | Job | Package |
| --- | --- | --- |
| Authorization server | Log the user in, issue an `at+jwt` with `cnf.jkt`, handle PAR and PKCE | `oidc-provider` |
| Client | Hold the key, sign a proof per request, answer a nonce challenge | `openid-client` (or `oauth4webapi` underneath it) |
| Resource server | Check the token, the proof, and that they belong together | Lacewing + Antlion |

Nothing crosses between the rows. The client never sees your replay store,
and your API never makes a proof.

## The authorization server: `oidc-provider`

- **Turn on DPoP and the FAPI 2.0 profile.** `features.dPoP`, and
  `features.fapi` with `profile: "2.0"`. The profile brings PAR and PKCE with
  it.
- **Ask for JWT access tokens.** `oidc-provider` issues opaque tokens unless
  the resource server says otherwise, and Antlion v1 only reads JWTs.
  `features.resourceIndicators.getResourceServerInfo` has to return
  `accessTokenFormat: "jwt"` for your API. The default implementation of that
  function throws until you write one, so you will notice.
- **Its DPoP algorithms already fit.** `enabledJWA.dPoPSigningAlgValues`
  defaults to `ES256`, `Ed25519` and `EdDSA`. Add `PS256` if your clients use
  RSA keys; add nothing else.
- **Its nonces are its own.** `features.dPoP.nonceSecret` and `requireNonce`
  govern the token endpoint. Your API's nonces are separate, with a separate
  secret, and a client handles the two independently.

## The client: `openid-client`

```text
keyPair = generateKeyPair("ES256")            non-extractable by default
dpop    = getDPoPHandle(config, keyPair)

token   = authorization code grant, with DPoP: dpop
data    = fetchProtectedResource(config, token, url, method, ..., { DPoP: dpop })
```

- **One key and one handle for the session.** The same handle signs the token
  request and every API call. A new key means the tokens bound to the old one
  stop working, which is the point of binding them.
- **The nonce retry is already there.** `fetchProtectedResource` retries once
  when your API answers `use_dpop_nonce`, so turning nonces on in Antlion
  costs the client a round trip and no code.
- **Ed25519 proofs say `Ed25519`, not `EdDSA`.** `oauth4webapi` writes the
  fully-specified algorithm name from RFC 9864 into the proof header. Antlion
  accepts both names for an Ed25519 key, and nothing else under either name.
- **The `url` it fetches is the `htu` it signs.** Whatever string the client
  passes there, your API's `origin` has to produce the same thing.

## The resource server: Lacewing + Antlion

```text
accessToken = Lacewing access-token profile
  issuer:     the oidc-provider issuer
  audience:   the resource indicator the client asked for
  keys:       the issuer's jwks_uri
  algorithms: the ones the issuer signs access tokens with

dpop = Antlion profile
  token:  accessToken
  origin: the public origin clients call, as a URL parser prints it
  replay: a shared store once there is more than one node
  nonce:  "required" (with nonceSecrets) | "off"
```

The access-token `algorithms` are whatever `oidc-provider` signs tokens with,
which is a Lacewing decision. The proof algorithms are Antlion's FAPI set and
are not configured here.

## Where the three have to agree

| Thing | Set in | Must match |
| --- | --- | --- |
| Token format | `getResourceServerInfo` | `"jwt"`, or Antlion refuses every token |
| Audience | the resource indicator | Lacewing's `audience` |
| Proof algorithms | `dPoPSigningAlgValues` and the client's key | Antlion's set: `PS256`, `ES256`, Ed25519 as `EdDSA` or `Ed25519` |
| `htu` | the `url` the client fetches | Antlion's `origin` plus the path |
| Nonces | each server, separately | nothing; they are independent |

## When to use `oauth4webapi` instead

`oauth4webapi` has a resource-server check of its own,
`validateJwtAccessToken`, and it does the binding correctly: `cnf.jkt` is
compared against the proof key's thumbprint, `ath` is required, `htm` is exact,
and a bound token under the `Bearer` scheme is refused. If you are not on
Lacewing, it is the sensible choice, and you should not add Antlion to get
DPoP.

Where the two differ, as of 3.8.8:

| Behaviour | `validateJwtAccessToken` | Antlion |
| --- | --- | --- |
| A `Bearer` token with no `cnf` | accepted, unless you pass `requireDPoP: true` | refused |
| Proof `jti` replay | checked to be a string, not recorded | recorded once in a store you must supply |
| Server nonces | not checked; the docs say to check them afterwards | checked, when you turn them on |
| `htu` compared against | `request.url` | the configured `origin` plus the path |
| Proof age | 300 seconds either side of now, fixed | a window you size, under a ceiling |
| Proof algorithms by default | includes `RS256`/`384`/`512` and ML-DSA | the FAPI set only |
| The access token is verified by | its own validator, from the issuer's metadata | your Lacewing profile |

Every row on the left can be closed from outside: `requireDPoP: true`, a
`signingAlgorithms` list, a `jti` store and a nonce check after the call, and
a `Request` whose `url` you built from your public origin instead of from the
`Host` header. Done that way it is a good setup. Antlion exists for the case
where the profile is already a Lacewing one and those decisions should be
impossible to forget.

Do not run both on the same route. Two verifiers are two policies, and when
they disagree about a request you end up debugging the difference between
them instead of the request.
