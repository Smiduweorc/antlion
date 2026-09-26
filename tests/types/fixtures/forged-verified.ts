// NEGATIVE FIXTURE: must not compile (AL-bind.1). A DPoPVerifiedJwt comes
// out of verifyDPoPRequest and nowhere else.

import type { VerifiedJwt } from "lacewing";
import type { DPoPVerifiedJwt } from "../../../index.js";

declare const token: VerifiedJwt;

export const forged: DPoPVerifiedJwt = { token, jkt: "made-up", nextNonce: undefined };
