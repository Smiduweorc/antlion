---
title: Frameworks
---

# Frameworks

**`verifyDPoPRequest` reads a WHATWG `Request`. On Node's own `http`,
Express, Fastify and Koa, `fromNodeRequest` from `antlion-lacewing/node`
builds what it reads, and the refusal is a status and headers each framework
can send as they are.**

The Node, Express, Fastify and Koa code here is what
`tests/integration/frameworks.test.ts` runs against a real server, with the
route mounted under a prefix and requests sent over a socket.

## What the adapter does, and why

- **Headers come from `req.headersDistinct`.** Node's `req.headers` keeps
  only the first of two `Authorization` headers, so a duplicate would never
  reach Antlion. `headersDistinct` keeps both, and Antlion refuses them.
- **Only `Authorization` and `DPoP` are copied.** Nothing else is read.
- **The path is the one the client signed.** A mounted router rewrites
  `req.url`: Express keeps the original in `req.originalUrl`, which the
  adapter prefers, and Koa keeps it in `ctx.originalUrl`, which you pass.
  Fastify leaves `request.raw.url` alone.

The origin always comes from your profile, never from `Host`.

## A WHATWG `Request`

A handler that already has a `Request` needs no adapter:

```ts
const { token } = await verifyDPoPRequest(request, dpop);
// on refusal:
return new Response(null, error.refusal);
```

## Node's `http`

```ts
import { fromNodeRequest } from "antlion-lacewing/node";

const { token } = await verifyDPoPRequest(fromNodeRequest(req), dpop);
// on refusal:
res.writeHead(error.refusal.status, error.refusal.headers).end();
```

## Express

```ts
router.get("/accounts/:id", async (req, res) => {
	const { token } = await verifyDPoPRequest(fromNodeRequest(req), dpop);
	// on refusal:
	res.status(error.refusal.status).set(error.refusal.headers).end();
});
app.use("/api", router);
```

## Fastify

```ts
app.get("/accounts/:id", async (request, reply) => {
	const { token } = await verifyDPoPRequest(fromNodeRequest(request.raw), dpop);
	// on refusal:
	return reply.code(error.refusal.status).headers(error.refusal.headers).send();
});
```

## Koa

```ts
app.use(async (ctx) => {
	const { token } = await verifyDPoPRequest(fromNodeRequest(ctx.req, ctx.originalUrl), dpop);
	// on refusal:
	ctx.status = error.refusal.status;
	ctx.set(error.refusal.headers);
});
```

Pass `ctx.originalUrl`. Under `koa-mount`, `ctx.req.url` has lost the mount
prefix, and every proof would fail its `htu` check.

## Sending the next nonce

With `nonce: "required"`, a verified request carries `nextNonce`. Send it on
your response so the client does not need a 401 to learn it:

```ts
if (nextNonce !== undefined) {
	res.set({ "DPoP-Nonce": nextNonce, "Cache-Control": "no-store" }); // Express
}
```

`no-store` is RFC 9449 section 8.2: a cached response would hand a stale
nonce to the next request.
