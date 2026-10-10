/**
 * A real HTTP server on 127.0.0.1 for the live interop tests: a token
 * endpoint that issues Lacewing access tokens bound to the key in the
 * client's DPoP proof, and protected routes behind Antlion with nonces on.
 *
 * The token endpoint is test scaffolding, not an authorization server. It
 * reads the proof's key and nothing else, because what is under test is the
 * resource server, and a client can only reach it with a bound token.
 */

import http, { type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { calculateJwkThumbprint, decodeProtectedHeader, type JWK } from "jose";
import { newAccessToken } from "lacewing";
import { AntlionError, defineDPoPProfile, SingleProcessReplayStore, verifyDPoPRequest } from "../index.js";
import { fromNodeRequest } from "../node.js";
import { AUDIENCE, ISSUER, issuer, NONCE_SECRET, tokenProfile } from "./helpers.js";

export interface LiveServer {
	/** `http://127.0.0.1:<port>`, the origin the profile is built for. */
	readonly origin: string;
	/** Every request that reached a protected route, and how Antlion answered. */
	readonly seen: { code: string; dpop: string | undefined }[];
	close(): Promise<void>;
}

async function issueToken(req: IncomingMessage, res: ServerResponse): Promise<void> {
	const proof = req.headersDistinct.dpop?.[0];
	const jwk = proof === undefined ? undefined : (decodeProtectedHeader(proof).jwk as JWK | undefined);
	if (jwk === undefined) {
		res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: "invalid_dpop_proof" }));
		return;
	}
	const token = await newAccessToken()
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.subject("interop")
		.expiresIn("5m")
		.claim("cnf", { jkt: await calculateJwkThumbprint(jwk) })
		.sign(issuer.privateKey);
	res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
	res.end(JSON.stringify({ access_token: token, token_type: "DPoP", expires_in: 300 }));
}

export async function startLiveServer(): Promise<LiveServer> {
	const seen: LiveServer["seen"] = [];
	// Listen first: the profile needs the port, and the handler needs the profile.
	const server = http.createServer();
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	const dpop = defineDPoPProfile({
		token: tokenProfile(),
		origin,
		replay: new SingleProcessReplayStore({ maxEntries: 1000 }),
		nonce: "required",
		nonceSecrets: [NONCE_SECRET],
	});

	server.on("request", (req: IncomingMessage, res: ServerResponse) => {
		const handle = async (): Promise<void> => {
			// Drain the body; the token endpoint's form fields are not needed.
			for await (const _chunk of req);
			if (req.method === "POST" && req.url === "/token") return issueToken(req, res);
			try {
				const { token, nextNonce } = await verifyDPoPRequest(fromNodeRequest(req), dpop);
				seen.push({ code: "accepted", dpop: req.headersDistinct.dpop?.[0] });
				res.writeHead(200, {
					"content-type": "application/json",
					"dpop-nonce": nextNonce as string,
					"cache-control": "no-store",
				});
				res.end(JSON.stringify({ sub: token.payload.sub, path: req.url }));
			} catch (error) {
				if (!(error instanceof AntlionError) || error.refusal === undefined) throw error;
				seen.push({ code: error.code, dpop: req.headersDistinct.dpop?.[0] });
				res.writeHead(error.refusal.status, error.refusal.headers).end();
			}
		};
		handle().catch(() => res.writeHead(500).end());
	});

	return {
		origin,
		seen,
		close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
	};
}
