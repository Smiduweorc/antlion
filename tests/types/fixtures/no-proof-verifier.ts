// NEGATIVE FIXTURE: must not compile. There is no export that
// checks a proof without the token and the binding.

import { checkProof } from "../../../index.js";

export const verifier = checkProof;
