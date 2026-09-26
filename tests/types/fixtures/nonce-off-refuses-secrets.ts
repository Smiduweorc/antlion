// NEGATIVE FIXTURE: must not compile (AL-nonce.1). Secrets with nonces off
// means someone thinks nonces are on.

import { accessTokenProfile } from "lacewing";
import { defineDPoPProfile, SingleProcessReplayStore } from "../../../index.js";

declare const token: ReturnType<typeof accessTokenProfile>;

export const confused = defineDPoPProfile({
	token,
	origin: "https://api.example.com",
	replay: new SingleProcessReplayStore({ maxEntries: 10 }),
	nonce: "off",
	nonceSecrets: [new Uint8Array(32)],
});
