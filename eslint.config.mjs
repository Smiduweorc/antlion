import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
	{
		ignores: ["dist/**", "docs/**", "node_modules/**"],
	},
	js.configs.recommended,
	...tseslint.configs.recommended,
	{
		files: ["**/*.{js,mjs,cjs,ts,tsx}"],
		languageOptions: {
			parser: tseslint.parser,
		},
		rules: {
			quotes: ["error", "double"],
			indent: ["error", "tab"],
			"no-tabs": "off",
			"no-console": "error",
			"@typescript-eslint/no-unused-vars": [
				"error",
				{
					argsIgnorePattern: "^_",
					varsIgnorePattern: "^_",
					caughtErrorsIgnorePattern: "^_",
				},
			],
			"@typescript-eslint/no-unused-expressions": [
				"error",
				{ allowTernary: true },
			],
			"@typescript-eslint/explicit-function-return-type": [
				"warn",
				{ allowExpressions: true },
			],
			// Verifying against a key carried in the JWT's own header is right
			// for a DPoP proof and a forgery for an access token (AL-key.1).
			"no-restricted-imports": [
				"error",
				{
					paths: [
						{
							name: "jose",
							importNames: ["EmbeddedJWK"],
							message: "EmbeddedJWK belongs to src/proof.ts alone.",
						},
					],
				},
			],
		},
	},
	{
		files: ["src/proof.ts"],
		rules: {
			"no-restricted-imports": "off",
		},
	},
	{
		// The compliance gate and its runner are CLIs: printing to the console
		// is their whole job.
		files: ["tools/**/*.ts"],
		rules: {
			"no-console": "off",
		},
	}
);
