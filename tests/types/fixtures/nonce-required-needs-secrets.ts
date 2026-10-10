// NEGATIVE FIXTURE: must not compile. Nonces without a secret
// could only be predictable or per-node.

import { accessTokenProfile } from "lacewing";
import { defineDPoPProfile, SingleProcessReplayStore } from "../../../index.js";

declare const token: ReturnType<typeof accessTokenProfile>;

export const noSecrets = defineDPoPProfile({
	token,
	origin: "https://api.example.com",
	replay: new SingleProcessReplayStore({ maxEntries: 10 }),
	nonce: "required",
});
