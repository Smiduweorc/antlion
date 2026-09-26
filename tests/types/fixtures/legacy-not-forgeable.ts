// NEGATIVE FIXTURE: must not compile (AL-alg.2). RS256 comes from
// antlion-lacewing/legacy, not from an object literal.

import type { DPoPProfileOptions } from "../../../index.js";

export const legacy: DPoPProfileOptions["legacyAlgorithms"] = [{ name: "RS256" }];
