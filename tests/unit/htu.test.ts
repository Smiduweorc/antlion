import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { normalizeHtu } from "../../src/htu.js";

test("normalizeHtu applies RFC 3986 section 6.2.2 and 6.2.3, case by case", () => {
	const cases: [string, string | undefined][] = [
		["https://api.example.com/a", "https://api.example.com/a"],
		["HTTPS://API.Example.COM/a", "https://api.example.com/a"],
		["https://api.example.com", "https://api.example.com/"],
		["https://api.example.com:443/a", "https://api.example.com/a"],
		["http://api.example.com:80/a", "http://api.example.com/a"],
		["https://api.example.com:8443/a", "https://api.example.com:8443/a"],
		["https://api.example.com/a/./b/../c", "https://api.example.com/a/c"],
		["https://api.example.com/a/%2E%2E/c", "https://api.example.com/c"],
		["https://api.example.com/%7euser", "https://api.example.com/~user"],
		["https://api.example.com/%41%2d%5F", "https://api.example.com/A-_"],
		["https://api.example.com/a%2fb", "https://api.example.com/a%2Fb"],
		["https://api.example.com/%e2%82%ac", "https://api.example.com/%E2%82%AC"],
		["https://api.example.com/%zz", "https://api.example.com/%zz"],
		["https://api.example.com/a?b=c#d", "https://api.example.com/a"],
		["https://api.example.com/a#", "https://api.example.com/a"],
		["https://xn--bcher-kva.example/a", "https://xn--bcher-kva.example/a"],
		["https://b\u00fccher.example/a", "https://xn--bcher-kva.example/a"],
		["https://[::1]:8443/a", "https://[::1]:8443/a"],
		["https://user@api.example.com/a", undefined],
		["https://:pw@api.example.com/a", undefined],
		["ftp://api.example.com/a", undefined],
		["javascript:alert(1)", undefined],
		["/a", undefined],
		["", undefined],
		["not a url", undefined],
	];
	for (const [input, expected] of cases) {
		assert.equal(normalizeHtu(input), expected, input);
	}
});

test("normalizeHtu is idempotent on every URL it accepts", () => {
	fc.assert(
		fc.property(fc.webUrl({ withQueryParameters: true, withFragments: true }), (url) => {
			const once = normalizeHtu(url);
			fc.pre(once !== undefined);
			assert.equal(normalizeHtu(once), once);
		}),
		{ numRuns: 1000 }
	);
});

test("normalizeHtu never keeps a query or a fragment", () => {
	fc.assert(
		fc.property(fc.webUrl({ withQueryParameters: true, withFragments: true }), (url) => {
			const normalized = normalizeHtu(url);
			fc.pre(normalized !== undefined);
			assert.equal(normalized.includes("?"), false);
			assert.equal(normalized.includes("#"), false);
		}),
		{ numRuns: 1000 }
	);
});
