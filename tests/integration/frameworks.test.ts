/**
 * The Node adapter under real servers. Each framework mounts the route under
 * a prefix, because that is where `req.url` stops being the path the client
 * signed, and requests go over a real socket so duplicate headers reach the
 * server as two headers rather than one joined value.
 */

import { after, test } from "node:test";
import assert from "node:assert/strict";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import Fastify from "fastify";
import Koa from "koa";
import mount from "koa-mount";
import { AntlionError, defineDPoPProfile, SingleProcessReplayStore, verifyDPoPRequest, type DPoPProfile } from "../../index.js";
import { fromNodeRequest } from "../../node.js";
import { clientKey, NONCE_SECRET, ORIGIN, proofFor, tokenFor, tokenProfile, type ClientKey } from "../helpers.js";

const PATH = "/api/accounts/42";

function dpopProfile(nonce: "off" | "required"): DPoPProfile {
	const common = { token: tokenProfile(), origin: ORIGIN, replay: new SingleProcessReplayStore({ maxEntries: 100 }) };
	return nonce === "off"
		? defineDPoPProfile({ ...common, nonce })
		: defineDPoPProfile({ ...common, nonce, nonceSecrets: [NONCE_SECRET] });
}

type Outcome = { status: number; headers: Record<string, string>; body: unknown };

/** Verify, and turn the result or the refusal into status, headers and body. */
async function decide(request: ReturnType<typeof fromNodeRequest>, dpop: DPoPProfile): Promise<Outcome> {
	try {
		const { token, nextNonce } = await verifyDPoPRequest(request, dpop);
		const headers: Record<string, string> = nextNonce === undefined ? {} : { "DPoP-Nonce": nextNonce, "Cache-Control": "no-store" };
		return { status: 200, headers, body: { sub: token.payload.sub } };
	} catch (error) {
		if (error instanceof AntlionError && error.refusal !== undefined) {
			return { status: error.refusal.status, headers: { ...error.refusal.headers }, body: { code: error.code } };
		}
		throw error;
	}
}

const servers: { name: string; start: (dpop: DPoPProfile) => Promise<{ port: number; close: () => Promise<void> }> }[] = [
	{
		name: "node:http",
		async start(dpop) {
			const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
				void decide(fromNodeRequest(req), dpop).then(({ status, headers, body }) => {
					res.writeHead(status, { ...headers, "content-type": "application/json" }).end(JSON.stringify(body));
				});
			});
			return listen(server);
		},
	},
	{
		name: "Express, under a mounted router",
		async start(dpop) {
			const app = express();
			const router = express.Router();
			router.get("/accounts/42", async (req, res) => {
				const { status, headers, body } = await decide(fromNodeRequest(req), dpop);
				res.status(status).set(headers).json(body);
			});
			app.use("/api", router);
			return listen(http.createServer(app));
		},
	},
	{
		name: "Fastify, under a route prefix",
		async start(dpop) {
			const app = Fastify();
			await app.register(
				async (scope) => {
					scope.get("/accounts/42", async (request, reply) => {
						const { status, headers, body } = await decide(fromNodeRequest(request.raw), dpop);
						return reply.code(status).headers(headers).send(body);
					});
				},
				{ prefix: "/api" }
			);
			await app.listen({ port: 0, host: "127.0.0.1" });
			return { port: (app.server.address() as AddressInfo).port, close: () => app.close() };
		},
	},
	{
		name: "Koa, under koa-mount",
		async start(dpop) {
			const inner = new Koa();
			inner.use(async (ctx) => {
				const { status, headers, body } = await decide(fromNodeRequest(ctx.req, ctx.originalUrl), dpop);
				ctx.status = status;
				ctx.set(headers);
				ctx.body = body;
			});
			const app = new Koa();
			app.use(mount("/api", inner));
			return listen(http.createServer(app.callback()));
		},
	},
];

function listen(server: http.Server): Promise<{ port: number; close: () => Promise<void> }> {
	return new Promise((resolve) => {
		server.listen(0, "127.0.0.1", () =>
			resolve({
				port: (server.address() as AddressInfo).port,
				close: () => new Promise((done) => server.close(() => done())),
			})
		);
	});
}

/** Send a GET with headers exactly as listed, repeats included. */
function send(port: number, headers: [string, string][]): Promise<Outcome> {
	const raw = [["Host", "api.example.com"], ...headers].flat();
	return new Promise((resolve, reject) => {
		const req = http.request({ host: "127.0.0.1", port, path: `${PATH}?page=1`, method: "GET", headers: raw }, (res) => {
			let text = "";
			res.setEncoding("utf8");
			res.on("data", (chunk: string) => (text += chunk));
			res.on("end", () => {
				const flat: Record<string, string> = {};
				for (const [name, value] of Object.entries(res.headers)) flat[name] = String(value);
				resolve({ status: res.statusCode ?? 0, headers: flat, body: text === "" ? undefined : JSON.parse(text) });
			});
		});
		req.on("error", reject);
		req.end();
	});
}

async function signed(key: ClientKey, token: string, payload: Record<string, unknown> = {}): Promise<string> {
	return proofFor(key, token, { payload: { htu: `${ORIGIN}${PATH}`, ...payload } }, Date.now());
}

const running: (() => Promise<void>)[] = [];
after(async () => {
	await Promise.all(running.map((close) => close()));
});

for (const framework of servers) {
	test(`[AL-node.1] ${framework.name}: a valid request verifies against the full path the client signed`, async () => {
		const server = await framework.start(dpopProfile("off"));
		running.push(server.close);
		const key = await clientKey();
		const token = await tokenFor(key.jkt);
		const outcome = await send(server.port, [
			["Authorization", `DPoP ${token}`],
			["DPoP", await signed(key, token)],
		]);
		assert.equal(outcome.status, 200, JSON.stringify(outcome.body));
		assert.deepEqual(outcome.body, { sub: "user-42" });
	});

	test(`[AL-node.1] [AL-hdr.2] ${framework.name}: two Authorization headers on the wire are a 400`, async () => {
		const server = await framework.start(dpopProfile("off"));
		running.push(server.close);
		const key = await clientKey();
		const token = await tokenFor(key.jkt);
		const outcome = await send(server.port, [
			["Authorization", `DPoP ${token}`],
			["Authorization", `DPoP ${token}`],
			["DPoP", await signed(key, token)],
		]);
		assert.equal(outcome.status, 400);
		assert.equal(outcome.headers["www-authenticate"], "DPoP error=\"invalid_request\", algs=\"ES256 PS256 EdDSA Ed25519\"");
		assert.deepEqual(outcome.body, { code: "duplicate-authorization" });
	});

	test(`[AL-node.1] [9449-4.3.1] ${framework.name}: two DPoP headers on the wire are refused`, async () => {
		const server = await framework.start(dpopProfile("off"));
		running.push(server.close);
		const key = await clientKey();
		const token = await tokenFor(key.jkt);
		const outcome = await send(server.port, [
			["Authorization", `DPoP ${token}`],
			["DPoP", await signed(key, token)],
			["DPoP", await signed(key, token)],
		]);
		assert.equal(outcome.status, 401);
		assert.match(outcome.headers["www-authenticate"] ?? "", /error="invalid_dpop_proof"/);
		assert.deepEqual(outcome.body, { code: "duplicate-proof" });
	});

	test(`[AL-node.1] [9449-9.1] ${framework.name}: the nonce challenge and its retry survive the framework`, async () => {
		const server = await framework.start(dpopProfile("required"));
		running.push(server.close);
		const key = await clientKey();
		const token = await tokenFor(key.jkt);
		const challenge = await send(server.port, [
			["Authorization", `DPoP ${token}`],
			["DPoP", await signed(key, token)],
		]);
		assert.equal(challenge.status, 401);
		assert.match(challenge.headers["www-authenticate"] ?? "", /error="use_dpop_nonce"/);
		assert.equal(challenge.headers["cache-control"], "no-store");
		const nonce = challenge.headers["dpop-nonce"];
		assert.equal(typeof nonce, "string");
		const retry = await send(server.port, [
			["Authorization", `DPoP ${token}`],
			["DPoP", await signed(key, token, { nonce })],
		]);
		assert.equal(retry.status, 200, JSON.stringify(retry.body));
		assert.equal(typeof retry.headers["dpop-nonce"], "string");
	});
}

test("[AL-node.1] under a mounted router, req.url alone would name the wrong URI", async () => {
	// The reason the adapter prefers originalUrl: without it, Express behind
	// app.use("/api", router) would compare htu against /accounts/42.
	const key = await clientKey();
	const token = await tokenFor(key.jkt);
	const headersDistinct = { authorization: [`DPoP ${token}`], dpop: [await signed(key, token)] };
	const trimmed = { method: "GET", url: "/accounts/42", headersDistinct };
	const error = await verifyDPoPRequest(fromNodeRequest(trimmed), dpopProfile("off")).catch((e: unknown) => e);
	assert.equal((error as AntlionError).code, "htu-mismatch");
	const withOriginal = { ...trimmed, originalUrl: PATH, headersDistinct: { ...headersDistinct, dpop: [await signed(key, token)] } };
	assert.equal((await verifyDPoPRequest(fromNodeRequest(withOriginal), dpopProfile("off"))).jkt, key.jkt);
});

test("[AL-node.1] an explicit url wins over originalUrl and url", async () => {
	const request = fromNodeRequest({ method: "GET", url: "/a", originalUrl: "/b", headersDistinct: {} }, "/c");
	assert.equal(request.url, "/c");
	assert.equal(fromNodeRequest({ method: "GET", url: "/a", originalUrl: "/b", headersDistinct: {} }).url, "/b");
	assert.equal(fromNodeRequest({ method: "GET", url: "/a", headersDistinct: {} }).url, "/a");
});

test("[AL-node.1] only Authorization and DPoP are copied, repeats kept", () => {
	const request = fromNodeRequest({
		method: "POST",
		url: "/",
		headersDistinct: { authorization: ["DPoP a", "DPoP b"], dpop: ["p"], cookie: ["secret=1"], host: ["evil.example.com"] },
	});
	assert.equal(request.method, "POST");
	assert.equal(request.headers.get("authorization"), "DPoP a, DPoP b");
	assert.equal(request.headers.get("dpop"), "p");
	assert.deepEqual([...request.headers.keys()].sort(), ["authorization", "dpop"]);
});

test("[AL-node.1] something that is not a Node request is refused as invalid-request", () => {
	for (const value of [null, {}, { headers: { authorization: "DPoP x" } }, { headersDistinct: null }]) {
		assert.throws(() => fromNodeRequest(value as never), { code: "invalid-request" });
	}
});

test("[AL-node.1] a missing method or url becomes a request verifyDPoPRequest refuses as invalid-request", async () => {
	for (const req of [{ url: "/", headersDistinct: {} }, { method: "GET", headersDistinct: {} }]) {
		const error = await verifyDPoPRequest(fromNodeRequest(req), dpopProfile("off")).catch((e: unknown) => e);
		assert.equal((error as AntlionError).code, "invalid-request");
	}
});
