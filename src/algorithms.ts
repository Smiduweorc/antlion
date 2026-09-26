/**
 * The FAPI 2.0 proof algorithms. Ed25519 is listed under both names: panva's
 * clients write RFC 9864's `Ed25519` into the proof header and never
 * `EdDSA`, so accepting only `EdDSA` would refuse every one of them.
 *
 * `none` and HMAC are not on the list and nothing adds them. The key type,
 * curve and minimum size for each name come from Lacewing's registry through
 * `lacewing/extension`, so the two packages cannot disagree about them.
 */
export const PROOF_ALGORITHMS: readonly string[] = Object.freeze(["ES256", "PS256", "EdDSA", "Ed25519"]);

declare const legacyBrand: unique symbol;

/**
 * A legacy proof algorithm, obtainable only from `antlion-lacewing/legacy`.
 * Passing one in `legacyAlgorithms` is the line in your code that says you
 * accept proofs FAPI 2.0 does not.
 */
export interface LegacyProofAlgorithm {
	readonly name: "RS256";
	readonly [legacyBrand]: true;
}
