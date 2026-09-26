/**
 * `htu` comparison (RFC 9449 section 4.3, check 9).
 *
 * Both sides go through {@link normalizeHtu} and are then compared as
 * strings. The WHATWG URL parser does most of RFC 3986 section 6.2.2 and all
 * of 6.2.3: scheme and host lowercased, default port dropped, dot segments
 * removed (including `%2E` spellings of them), an empty path made `/`. What
 * it leaves undone is the percent-encoding half of 6.2.2, so that is done
 * here: hex digits uppercased, and escapes of unreserved characters decoded.
 */

const PERCENT_ESCAPE = /%[0-9A-Fa-f]{2}/g;
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

function normalizeEscape(escape: string): string {
	const char = String.fromCharCode(parseInt(escape.slice(1), 16));
	return UNRESERVED.test(char) ? char : escape.toUpperCase();
}

/**
 * The comparable form of an absolute http(s) URI: scheme, authority and
 * path, with the query and fragment gone. Undefined for anything that is not
 * an absolute http or https URI, and for a URI carrying user information,
 * which no request target has.
 */
export function normalizeHtu(value: string): string | undefined {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return undefined;
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") return undefined;
	if (url.username !== "" || url.password !== "") return undefined;
	return `${url.protocol}//${url.host}${url.pathname.replace(PERCENT_ESCAPE, normalizeEscape)}`;
}
