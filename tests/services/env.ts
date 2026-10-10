import process from "node:process";

/**
 * A connection URL the service suite cannot run without. Missing is a
 * failure, never a skip: a store suite that quietly skips has proven nothing.
 */
export function serviceUrl(name: "ANTLION_TEST_REDIS_URL" | "ANTLION_TEST_POSTGRES_URL"): string {
	const url = process.env[name];
	if (url === undefined || url === "") {
		throw new Error(
			`${name} is not set. npm run test:services needs a real Redis and Postgres; ` +
				"see the services job in .github/workflows/ci.yml for the containers it runs against."
		);
	}
	return url;
}

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
