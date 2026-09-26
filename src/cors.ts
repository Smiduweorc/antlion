/**
 * Header names a browser client needs your CORS policy to allow. Antlion
 * sends no CORS headers itself; which origins may call your API is yours to
 * decide.
 */

/** For `Access-Control-Allow-Headers`: the client has to be allowed to send these. */
export const DPOP_REQUEST_HEADERS: readonly string[] = Object.freeze(["Authorization", "DPoP"]);

/** For `Access-Control-Expose-Headers`: the client has to be allowed to read these. */
export const DPOP_RESPONSE_HEADERS: readonly string[] = Object.freeze(["WWW-Authenticate", "DPoP-Nonce"]);
