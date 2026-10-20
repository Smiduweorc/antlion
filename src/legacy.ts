/**
 * LEGACY INTEROP. `RS256` proofs, for clients that cannot sign anything the
 * FAPI 2.0 set allows. PKCS#1 v1.5 is what RSA-PSS replaced; prefer `PS256`
 * wherever you control the client.
 */

import { LEGACY_RS256 } from "lacewing/legacy/rsa";
import type { LegacyProofAlgorithm } from "./algorithms.js";

const RS256 = Object.freeze({ name: "RS256", lacewing: LEGACY_RS256 }) as LegacyProofAlgorithm;

/**
 * Accept `RS256` proofs on a profile:
 * `defineDPoPProfile({ ..., legacyAlgorithms: [legacyRS256Proofs()] })`.
 *
 * It carries Lacewing's `LEGACY_RS256` descriptor and changes nothing outside
 * the profile it is passed to: no other DPoP profile, and no Lacewing
 * profile, accepts RS256 because of it.
 */
export function legacyRS256Proofs(): LegacyProofAlgorithm {
	return RS256;
}
