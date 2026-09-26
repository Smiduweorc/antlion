// Public surface. Everything reachable from here is API you have to keep;
// anything else under `src/` is internal and free to change.
//
// The `.js` extension is required: under `nodenext` resolution the specifier
// must match the emitted file, not the `.ts` source.

export { DPOP_REQUEST_HEADERS, DPOP_RESPONSE_HEADERS } from "./src/cors.js";
export { AntlionError } from "./src/errors.js";
export { defineDPoPProfile } from "./src/profile.js";
export { SingleProcessReplayStore } from "./src/replay-store.js";
export { verifyDPoPRequest } from "./src/verify.js";

export type { LegacyProofAlgorithm } from "./src/algorithms.js";
export type { AntlionErrorCode, DPoPRefusal } from "./src/errors.js";
export type { DPoPProfile, DPoPProfileBaseOptions, DPoPProfileOptions } from "./src/profile.js";
export type { ReplayStore, SingleProcessReplayStoreOptions } from "./src/replay-store.js";
export type { DPoPRequest, DPoPVerifiedJwt } from "./src/verify.js";
