// NEGATIVE FIXTURE: must not compile (AL-nonce.1). Nonce mode has no default;
// leaving it out is not a choice.

import { accessTokenProfile } from "lacewing";
import { defineDPoPProfile, SingleProcessReplayStore } from "../../../index.js";

declare const token: ReturnType<typeof accessTokenProfile>;

export const noNonceMode = defineDPoPProfile({
	token,
	origin: "https://api.example.com",
	replay: new SingleProcessReplayStore({ maxEntries: 10 }),
});
