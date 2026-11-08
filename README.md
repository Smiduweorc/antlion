# antlion

![antlion logo](https://github.com/Smiduweorc/antlion/blob/master/assets/logo.png?raw=true)

DPoP for APIs that already verify access tokens with [Lacewing](https://github.com/Smiduweorc/lacewing). You wrap your Lacewing profile and call `verifyDPoPRequest(request, profile)`; it returns the verified token or throws a refusal you can send as-is.

It implements the resource-server side of [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449), with the FAPI 2.0 proof algorithms (`PS256`, `ES256`, and Ed25519 as either `EdDSA` or `Ed25519`, which is what panva's clients send). `RS256` is available only through the `antlion-lacewing/legacy` import. [jose](https://github.com/panva/jose) is the one direct dependency, used only for the proof.

## Install

```sh
npm install antlion-lacewing lacewing
```

Node 24 or later (CI runs Node 24 on Linux, macOS and Windows). Lacewing 3 is a peer dependency.

## Example

```ts
import { accessTokenProfile } from "lacewing";
import { AntlionError, defineDPoPProfile, SingleProcessReplayStore, verifyDPoPRequest } from "antlion-lacewing";

const dpop = defineDPoPProfile({
	token: accessTokenProfile({
		issuer: "https://auth.example.com",
		audience: "https://api.example.com",
		algorithms: ["ES256"],
		keys: {
			jwksUri: "https://auth.example.com/jwks",
			cacheTtlSeconds: 300, // Lacewing makes you pick these three
			cooldownSeconds: 30,
			timeoutMs: 2000,
		},
	}),
	origin: "https://api.example.com",
	replay: new SingleProcessReplayStore({ maxEntries: 100_000 }),
	nonce: "off",
});

async function handle(request: Request): Promise<Response> {
	try {
		const { token } = await verifyDPoPRequest(request, dpop);
		return Response.json({ hello: token.payload.sub });
	} catch (error) {
		if (error instanceof AntlionError && error.refusal !== undefined) {
			// error.code says which check failed. Log it; don't send it.
			return new Response(null, error.refusal);
		}
		throw error;
	}
}
```

On Node's `http`, Express, Fastify or Koa, build the request with `fromNodeRequest(req)` from `antlion-lacewing/node` ([Frameworks](./guides/frameworks.md)).

With more than one process, every process needs the same store: `RedisReplayStore` (`antlion-lacewing/redis`) or `PostgresReplayStore` (`antlion-lacewing/postgres`), on the client you already have ([Deployment](./guides/deployment.md)).

To turn nonces on, pass `nonce: "required"` and `nonceSecrets: [secret]`, at least 32 random bytes and the same on every node. A verified request then carries `nextNonce` to send back as `DPoP-Nonce`.

## The options

`token`, `origin`, `replay` and `nonce` have no default.

- `origin` is the origin your clients sign against, written the way a URL parser prints it: lowercase host, no default port, no trailing slash. `htu` must equal it plus the request path, after RFC 3986 normalisation, without query or fragment. `Host`, `X-Forwarded-*` and `Forwarded` are never read. A malformed origin is refused when the profile is built.
- `replay` remembers each accepted proof for `maxProofAge` plus 6 seconds. If the store errors, or the single-process one is full, the request is refused.
- `nonce: "required"` costs an extra round trip whenever a client's nonce is stale, and stops proofs being signed in advance with a wrong clock. `"off"` trusts the client's `iat`. Nonces are stateless HMACs, so nodes only share the secret.
- `maxProofAge` defaults to 60 seconds, at most 300 (what oauth4webapi allows). A client clock up to 5 seconds ahead is accepted; that is fixed.

## How it works

`verifyDPoPRequest` runs these checks in this order and stops at the first refusal:

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

There is no exported function that checks a proof without the binding. The replay store is asked last, so unauthenticated requests never write to it. The key in the proof header is used for the proof signature and nothing else.

A refusal is a 401 with a `WWW-Authenticate: DPoP` challenge listing the accepted algorithms, plus `DPoP-Nonce` and `Cache-Control: no-store` when a fresh nonce is due. A duplicated or malformed `Authorization` header is a 400 `invalid_request` (RFC 6750). The client sees only `invalid_request`, `invalid_token`, `invalid_dpop_proof` or `use_dpop_nonce`; the exact reason is `error.code`, for your logs.

## Not included

- Creating proofs and retrying on a nonce challenge. Use [oauth4webapi](https://github.com/panva/oauth4webapi) or [openid-client](https://github.com/panva/openid-client).
- Issuing bound tokens, `dpop_jkt`, PAR, PKCE. Use [oidc-provider](https://github.com/panva/node-oidc-provider), Keycloak or your authorization server.
- Accepting `Bearer` and `DPoP` on one route while you migrate. Put the old traffic on its own route with a plain Lacewing profile.
- mTLS (RFC 8705).
- Opaque tokens and introspection. JWT access tokens (RFC 9068) only.
- Verifying tokens without Lacewing. Use oauth4webapi's `validateJwtAccessToken`; [With panva's tools](./guides/panva.md) lists what to add around it.

## Known quirks

- It needs Lacewing 3. Antlion uses Lacewing's algorithm table, header reading, duration parsing, JSON reading and profile check through `lacewing/extension`. A new Antlion major usually ships with the Lacewing major it needs. Legacy `RS256` proofs use Lacewing's `LEGACY_RS256` descriptor, which works only on the profile it is passed to.
- Profiles can't be hand-built or copied. `defineDPoPProfile` refuses a token profile Lacewing's `defineProfile` didn't make, and `verifyDPoPRequest` refuses a DPoP profile `defineDPoPProfile` didn't make, `{ ...profile }` included. Both throw `invalid-options`.
- Browsers need CORS. Put `DPOP_REQUEST_HEADERS` in `Access-Control-Allow-Headers` and `DPOP_RESPONSE_HEADERS` in `Access-Control-Expose-Headers`.
- Node drops a duplicate `Authorization` header: `req.headers` keeps the first one. `fromNodeRequest` reads `req.headersDistinct`; if you build the request yourself, do the same, or a second header goes unnoticed.
- A throwing `unsafeClaimValidators` function is a refused token (`token-invalid`, your error at the end of the `cause` chain). An error Lacewing does not catch, such as from your `unsafeCustomKeySource` or `now`, comes back unchanged.
- There are two clocks. The DPoP profile's `now` drives proof freshness and nonces; the Lacewing profile's `now` judges the token's `exp`. If you set one, set both to the same function.
- Nodes sharing a replay store need clocks within one second of each other, or a proof can be accepted once by the fast node and again by the slow one ([Deployment](./guides/deployment.md#clocks)).
- The Redis and Postgres stores are tested in CI against a single Redis 8 and a single Postgres 18. Redis Cluster is not tested.
- The [performance](./guides/performance.md) numbers are from one laptop.

## Guides

- [Boundaries](./guides/boundaries.md)
- [With panva's tools](./guides/panva.md)
- [Frameworks](./guides/frameworks.md)
- [Deployment](./guides/deployment.md)
- [Threat model](./guides/threat-model.md)
- [Verification](./guides/verification.md)
- [Performance](./guides/performance.md)
- [Security](./SECURITY.md), [Changelog](./CHANGELOG.md), [Notice](./NOTICE.md)

The API reference is generated by TypeDoc and includes these pages.

## Why it exists

Lacewing only does bearer tokens. A Lacewing user needed FAPI 2.0, which requires tokens bound to the client, and DPoP is the binding that still works behind a TLS-terminating proxy.

oauth4webapi does validate DPoP-bound access tokens, but it is a general OAuth client with its own settings. Under Lacewing that would be two policy layers that can disagree about what "valid" means.

Mistakes in DPoP verifiers that pass a test suite which only sends valid requests:

- Verifying the proof and the token, and never comparing `cnf.jkt`
- Accepting a DPoP-bound token under the `Bearer` scheme
- Accepting a token with no `cnf.jkt` under the `DPoP` scheme
- Verifying the access token against the key in the proof header
- Comparing `htu` by prefix, or against a URL rebuilt from `X-Forwarded-Host`
- Treating `ath` as optional
- Tracking `jti` in memory on each of twenty nodes, or failing open when the store is down
- Letting the header pick the algorithm

Antlion refuses all of these except the twenty memory stores, which a library can't see from inside one process. That is why the in-memory store is called `SingleProcessReplayStore` and the store has no default.

## License

MIT. Includes code adapted from [jose](https://github.com/panva/jose) by Filip Skokan (panva); see [NOTICE.md](./NOTICE.md).

## Lore

Antlions and lacewings are both Neuroptera, and an adult antlion is easy to mistake for a lacewing. The larva is the famous part: some species dig a cone in loose sand at the steepest angle the sand will hold, and wait at the bottom for an ant to step over the rim.
