// NEGATIVE FIXTURE: must not compile. RS256 comes from
// antlion-lacewing/legacy, not from an object literal.

import type { DPoPProfileOptions } from "../../../index.js";

export const legacy: DPoPProfileOptions["legacyAlgorithms"] = [{ name: "RS256" }];
