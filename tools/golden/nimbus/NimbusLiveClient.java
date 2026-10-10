/*
 * A Nimbus OAuth 2.0 SDK client against a live Antlion server, driven by
 * tests/services/nimbus-live.test.ts. Given the server's origin, it obtains a
 * DPoP-bound token, calls a protected route without a nonce, retries with
 * the nonce it was given, then tries a replay, a stale proof and another
 * key's proof. It prints one JSON object of the statuses it saw.
 *
 *     cd tools/golden/nimbus
 *     mvn -q dependency:copy-dependencies -DoutputDirectory=lib
 *     java -cp "lib/*" NimbusLiveClient.java http://127.0.0.1:PORT
 */

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

public class NimbusLiveClient {
	static final HttpClient HTTP = HttpClient.newHttpClient();

	public static void main(String[] args) throws Exception {
		URI origin = URI.create(args[0]);
		Map<String, Object> seen = new LinkedHashMap<>();
		run(origin, "es256", new ECKeyGenerator(Curve.P_256).generate(), JWSAlgorithm.ES256, seen);
		run(origin, "ps256", new RSAKeyGenerator(2048).generate(), JWSAlgorithm.PS256, seen);
		run(origin, "ed25519", new OctetKeyPairGenerator(Curve.Ed25519).generate(), JWSAlgorithm.Ed25519, seen);
		StringBuilder out = new StringBuilder("{");
		for (var entry : seen.entrySet()) {
			if (out.length() > 1) out.append(',');
			out.append('"').append(entry.getKey()).append("\":").append(entry.getValue());
		}
		System.out.println(out.append('}'));
	}

	static void run(URI origin, String name, JWK key, JWSAlgorithm alg, Map<String, Object> seen) throws Exception {
		var proofs = new DefaultDPoPProofFactory(key, alg);
		URI tokenEndpoint = origin.resolve("/token");
		URI resource = origin.resolve("/accounts/42");

		var tokenResponse = send(HttpRequest.newBuilder(tokenEndpoint)
			.header("DPoP", proofs.createDPoPJWT("POST", tokenEndpoint).serialize())
			.header("Content-Type", "application/x-www-form-urlencoded")
			.POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials")));
		String body = tokenResponse.body();
		var token = new DPoPAccessToken(body.replaceAll("^.*\"access_token\":\"([^\"]+)\".*$", "$1"));

		var challenge = get(resource, token, proofs.createDPoPJWT("GET", resource, token).serialize());
		seen.put(name + "_challenge", challenge.statusCode());
		var nonce = new Nonce(challenge.headers().firstValue("DPoP-Nonce").orElseThrow());

		String accepted = proofs.createDPoPJWT("GET", resource, token, nonce).serialize();
		seen.put(name + "_retry", get(resource, token, accepted).statusCode());
		seen.put(name + "_replay", get(resource, token, accepted).statusCode());

		Date anHourAgo = new Date(System.currentTimeMillis() - 3_600_000);
		String stale = proofs.createDPoPJWT(new JWTID(), "GET", resource, anHourAgo, token, nonce).serialize();
		seen.put(name + "_stale", get(resource, token, stale).statusCode());

		var thief = new DefaultDPoPProofFactory(new ECKeyGenerator(Curve.P_256).generate(), JWSAlgorithm.ES256);
		seen.put(name + "_other_key", get(resource, token, thief.createDPoPJWT("GET", resource, token, nonce).serialize()).statusCode());
	}

	static HttpResponse<String> get(URI uri, DPoPAccessToken token, String proof) throws Exception {
		return send(HttpRequest.newBuilder(uri).header("Authorization", token.toAuthorizationHeader()).header("DPoP", proof).GET());
	}

	static HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
		return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
	}
}
