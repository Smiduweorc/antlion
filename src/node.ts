import { AntlionError } from "./errors.js";
import type { DPoPRequest } from "./verify.js";

/**
 * The parts of a Node `IncomingMessage` the adapter reads. Express's `req`,
 * Fastify's `request.raw` and Koa's `ctx.req` all are one.
 */
export interface NodeRequestLike {
	readonly method?: string | undefined;
	readonly url?: string | undefined;
	/** Express keeps the path here before a mounted router trims `url`. */
	readonly originalUrl?: string | undefined;
	readonly headersDistinct: Readonly<Record<string, readonly string[] | undefined>>;
}

/**
 * Turn a Node request into what `verifyDPoPRequest` reads.
 *
 * Headers come from `headersDistinct`, because `req.headers` keeps only the
 * first of two `Authorization` headers and a duplicate would go unseen. Only
 * `Authorization` and `DPoP` are copied.
 *
 * The path is `url` if given, else Express's `originalUrl`, else `req.url`.
 * Pass it when something in front of you rewrote `req.url`: under
 * `koa-mount`, `ctx.req.url` has lost the mount prefix and only
 * `ctx.originalUrl` still has the path the client signed.
 *
 * @example
 * ```ts
 * verifyDPoPRequest(fromNodeRequest(req), dpop);                    // node:http, Express
 * verifyDPoPRequest(fromNodeRequest(request.raw), dpop);            // Fastify
 * verifyDPoPRequest(fromNodeRequest(ctx.req, ctx.originalUrl), dpop); // Koa
 * ```
 */
export function fromNodeRequest(req: NodeRequestLike, url?: string): DPoPRequest {
	const distinct = (req as NodeRequestLike | null)?.headersDistinct;
	if (typeof distinct !== "object" || distinct === null) {
		throw new AntlionError(
			"invalid-request",
			"fromNodeRequest() needs a Node IncomingMessage (Express req, Fastify request.raw, Koa ctx.req)"
		);
	}
	const headers = new Headers();
	for (const name of ["authorization", "dpop"]) {
		for (const value of distinct[name] ?? []) headers.append(name, value);
	}
	return { method: req.method ?? "", url: url ?? req.originalUrl ?? req.url ?? "", headers };
}
