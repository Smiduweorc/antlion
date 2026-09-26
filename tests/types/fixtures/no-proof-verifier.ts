// NEGATIVE FIXTURE: must not compile (AL-bind.1). There is no export that
// checks a proof without the token and the binding.

import { checkProof } from "../../../index.js";

export const verifier = checkProof;
