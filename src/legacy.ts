/**
 * LEGACY INTEROP. `RS256` proofs, for clients that cannot sign anything the
 * FAPI 2.0 set allows. PKCS#1 v1.5 is what RSA-PSS replaced; prefer `PS256`
 * wherever you control the client.
 */

import { enableLegacyRS256 } from "lacewing/legacy/rs256";
import type { LegacyProofAlgorithm } from "./algorithms.js";

const RS256 = Object.freeze({ name: "RS256" }) as LegacyProofAlgorithm;

/**
 * Accept `RS256` proofs on a profile:
 * `defineDPoPProfile({ ..., legacyAlgorithms: [legacyRS256Proofs()] })`.
 *
 * Calling it also calls Lacewing's `enableLegacyRS256()`, which puts `RS256`
 * in Lacewing's registry for the whole process. That makes RS256 keys
 * importable in Lacewing; no Lacewing profile accepts RS256 tokens unless its
 * own `algorithms` lists it.
 */
export function legacyRS256Proofs(): LegacyProofAlgorithm {
	enableLegacyRS256();
	return RS256;
}
