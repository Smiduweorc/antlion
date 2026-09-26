// The "antlion-lacewing/node" entry point: Node's http, Express, Fastify and
// Koa. Nothing in the root imports it, so a runtime with a WHATWG Request
// never loads it.

export { fromNodeRequest } from "./src/node.js";

export type { NodeRequestLike } from "./src/node.js";
