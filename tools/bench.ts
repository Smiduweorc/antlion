/**
 * Benchmark harness: `npm run bench`.
 *
 * Times verifyDPoPRequest on one core, one request at a time, with the
 * in-process replay store. Every accepted request carries a proof signed
 * beforehand, so signing is not in the numbers; verifying the proof, the
 * Lacewing access token (ES256), the binding and the store write are.
 * Refusals are timed on requests that fail at a known step, to show what an
 * early refusal costs next to a full verification.
 *
 * Prints a Markdown table with the machine it ran on. The same script runs
 * on a GitHub runner through .github/workflows/bench.yml, so the numbers in
 * the README can be re-run on hardware anyone can get.
 */

import type { webcrypto } from "node:crypto";
import { cpus, platform, release } from "node:os";
import { performance } from "node:perf_hooks";
import { accessTokenProfile, generateKeyPair, newAccessToken } from "lacewing";
import { base64url, calculateJwkThumbprint } from "jose";
import { AntlionError, defineDPoPProfile, SingleProcessReplayStore, verifyDPoPRequest, type DPoPProfile } from "../index.js";

const ORIGIN = "https://api.example.com";
const URL_ = `${ORIGIN}/accounts/42`;
const WARMUP = 200;
const RUNS = 2_000;

type Alg = "ES256" | "PS256" | "Ed25519";

const SIGN: Record<
	Alg,
	{
		generate: webcrypto.EcKeyGenParams | webcrypto.RsaHashedKeyGenParams | webcrypto.Algorithm;
		sign: webcrypto.EcdsaParams | webcrypto.RsaPssParams | webcrypto.Algorithm;
	}
> = {
	ES256: { generate: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" } },
	PS256: {
		generate: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		sign: { name: "RSA-PSS", saltLength: 32 },
	},
	Ed25519: { generate: { name: "Ed25519" }, sign: { name: "Ed25519" } },
};

const issuer = await generateKeyPair("ES256");
const tokenProfile = accessTokenProfile({
	issuer: "https://auth.example.com",
	audience: ORIGIN,
	algorithms: ["ES256"],
	keys: issuer.publicKey,
});

function profile(nonce: "off" | "required"): DPoPProfile {
	const common = { token: tokenProfile, origin: ORIGIN, replay: new SingleProcessReplayStore({ maxEntries: 100_000 }), maxProofAge: 300 };
	return nonce === "off"
		? defineDPoPProfile({ ...common, nonce })
		: defineDPoPProfile({ ...common, nonce, nonceSecrets: [crypto.getRandomValues(new Uint8Array(32))] });
}

const encode = (value: unknown): string => base64url.encode(JSON.stringify(value));

async function client(alg: Alg): Promise<{ token: string; proof: (claims?: Record<string, unknown>) => Promise<string> }> {
	const pair = (await crypto.subtle.generateKey(SIGN[alg].generate, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
	const full = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Record<string, string>;
	const jwk = Object.fromEntries(Object.entries(full).filter(([name]) => ["kty", "crv", "x", "y", "n", "e"].includes(name)));
	const token = await newAccessToken()
		.issuer("https://auth.example.com")
		.audience(ORIGIN)
		.subject("bench")
		.expiresIn("30m")
		.claim("cnf", { jkt: await calculateJwkThumbprint(jwk) })
		.sign(issuer.privateKey);
	const ath = base64url.encode(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))));
	const proof = async (claims: Record<string, unknown> = {}): Promise<string> => {
		const input = `${encode({ typ: "dpop+jwt", alg, jwk })}.${encode({
			jti: crypto.randomUUID(),
			htm: "GET",
			htu: URL_,
			iat: Math.floor(Date.now() / 1000),
			ath,
			...claims,
		})}`;
		const signature = await crypto.subtle.sign(SIGN[alg].sign, pair.privateKey, new TextEncoder().encode(input));
		return `${input}.${base64url.encode(new Uint8Array(signature))}`;
	};
	return { token, proof };
}

function request(token: string, proof: string): Request {
	return new Request(URL_, { headers: { authorization: `DPoP ${token}`, dpop: proof } });
}

interface Result {
	readonly name: string;
	readonly opsPerSecond: number;
	readonly p50: number;
	readonly p99: number;
}

/** Time `RUNS` calls after `WARMUP` untimed ones. `requests` holds one request per call. */
async function measure(name: string, requests: Request[], dpop: DPoPProfile, expect: "accept" | "refuse"): Promise<Result> {
	const latencies: number[] = [];
	for (const [i, req] of requests.entries()) {
		const start = performance.now();
		const accepted = await verifyDPoPRequest(req, dpop).then(
			() => true,
			() => false
		);
		const elapsed = performance.now() - start;
		if (accepted !== (expect === "accept")) throw new Error(`${name}: expected every request to ${expect}`);
		if (i >= WARMUP) latencies.push(elapsed);
	}
	const total = latencies.reduce((sum, ms) => sum + ms, 0);
	latencies.sort((a, b) => a - b);
	return {
		name,
		opsPerSecond: (latencies.length / total) * 1000,
		p50: latencies[Math.floor(latencies.length * 0.5)] as number,
		p99: latencies[Math.floor(latencies.length * 0.99)] as number,
	};
}

async function accepted(alg: Alg, nonce: "off" | "required"): Promise<Result> {
	const dpop = profile(nonce);
	const { token, proof } = await client(alg);
	let claims: Record<string, unknown> = {};
	if (nonce === "required") {
		const challenge = await verifyDPoPRequest(request(token, await proof()), dpop).catch((e: unknown) => e);
		if (!(challenge instanceof AntlionError) || challenge.code !== "nonce-missing") throw new Error("no nonce challenge");
		claims = { nonce: challenge.refusal?.headers["DPoP-Nonce"] };
	}
	const requests: Request[] = [];
	for (let i = 0; i < WARMUP + RUNS; i++) requests.push(request(token, await proof(claims)));
	return measure(`accepted, ${alg} proof${nonce === "required" ? ", nonces on" : ""}`, requests, dpop, "accept");
}

async function refused(name: string, make: (token: string, proof: string) => Request): Promise<Result> {
	const { token, proof } = await client("ES256");
	const one = await proof();
	const requests = Array.from({ length: WARMUP + RUNS }, () => make(token, one));
	return measure(name, requests, profile("off"), "refuse");
}

const results: Result[] = [
	await accepted("ES256", "off"),
	await accepted("Ed25519", "off"),
	await accepted("PS256", "off"),
	await accepted("ES256", "required"),
	await refused("refused: Bearer scheme", (token, proof) =>
		new Request(URL_, { headers: { authorization: `Bearer ${token}`, dpop: proof } })
	),
	await refused("refused: htu mismatch, before any signature", (token, proof) =>
		new Request(`${ORIGIN}/other`, { headers: { authorization: `DPoP ${token}`, dpop: proof } })
	),
	await refused("refused: bad proof signature", (token, proof) => {
		const [h, p, s] = proof.split(".") as [string, string, string];
		const flipped = `${s.slice(0, 10)}${s[10] === "A" ? "B" : "A"}${s.slice(11)}`;
		return request(token, `${h}.${p}.${flipped}`);
	}),
];

const cpu = cpus()[0]?.model.trim() ?? "unknown CPU";
console.log(`Node ${process.version}, ${platform()} ${release()}, ${cpu}. One request at a time, ${RUNS} timed after ${WARMUP} warm-up.\n`);
console.log("| Request | Per second | p50 | p99 |");
console.log("| --- | ---: | ---: | ---: |");
for (const r of results) {
	console.log(`| ${r.name} | ${Math.round(r.opsPerSecond).toLocaleString("en-US")} | ${r.p50.toFixed(3)} ms | ${r.p99.toFixed(3)} ms |`);
}
