// NEGATIVE FIXTURE: must not compile (AL-replay.1). A profile with no replay
// store is a profile that accepts every proof as often as it is sent.

import { accessTokenProfile } from "lacewing";
import { defineDPoPProfile } from "../../../index.js";

declare const token: ReturnType<typeof accessTokenProfile>;

export const noStore = defineDPoPProfile({
	token,
	origin: "https://api.example.com",
	nonce: "off",
});
