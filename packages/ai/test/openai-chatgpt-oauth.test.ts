import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { openaiChatGPTOAuth } from "../src/auth/oauth/openai-chatgpt.ts";
import type { OAuthCredential, ProviderAuthInteraction } from "../src/auth/types.ts";

const ISSUER = "https://auth.openai.com";
const TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token";
const JWKS_URL = "https://auth.openai.com/.well-known/jwks.json";
const REQUIRED_SCOPE = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const neverAbortedSignal = new AbortController().signal;
const DEVICE_ID = "e61bbe28-07ef-466d-8e5d-a344f94ab305";
const ACCOUNT = "user-account-1";

type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
let openaiKey: SigningKey;
let attackerKey: SigningKey;
let jwks: { keys: JWK[] };

beforeAll(async () => {
	const openai = await generateKeyPair("RS256");
	const attacker = await generateKeyPair("RS256");
	openaiKey = openai.privateKey;
	attackerKey = attacker.privateKey;
	jwks = { keys: [{ ...(await exportJWK(openai.publicKey)), kid: "openai-test", alg: "RS256", use: "sig" }] };
});

type IdTokenOptions = {
	key?: SigningKey;
	kid?: string;
	issuer?: string;
	audience?: string;
	subject?: string | null;
	nonce?: string | null;
	expiresAt?: number;
};

async function idToken(options: IdTokenOptions & { clientId: string; loginNonce?: string }): Promise<string> {
	const claims: Record<string, unknown> = {};
	const nonce = options.nonce === undefined ? options.loginNonce : options.nonce;
	if (nonce !== null && nonce !== undefined) claims.nonce = nonce;
	const jwt = new SignJWT(claims)
		.setProtectedHeader({ alg: "RS256", kid: options.kid ?? "openai-test" })
		.setIssuer(options.issuer ?? ISSUER)
		.setAudience(options.audience ?? options.clientId)
		.setIssuedAt()
		.setExpirationTime(options.expiresAt ?? Math.floor(Date.now() / 1000) + 3600);
	if (options.subject !== null) jwt.setSubject(options.subject ?? ACCOUNT);
	return jwt.sign(options.key ?? openaiKey);
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

type TokenRequest = { body: URLSearchParams; loginNonce?: string };

/** Serves OpenAI's JWKS and token endpoint; the token response is built per request. */
function stubAuthServer(
	token: (request: TokenRequest) => Promise<Record<string, unknown>> | Record<string, unknown>,
	session: { nonce?: string } = {},
) {
	const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
		const url = input instanceof Request ? input.url : String(input);
		if (url === JWKS_URL) return jsonResponse(jwks);
		expect(url).toBe(TOKEN_URL);
		return jsonResponse(await token({ body: new URLSearchParams(String(init?.body)), loginNonce: session.nonce }));
	});
	vi.stubGlobal("fetch", fetchMock);
	return fetchMock;
}

function tokenResponse(scope = REQUIRED_SCOPE, extra: Record<string, unknown> = {}) {
	return {
		access_token: "access-token",
		refresh_token: "refresh-token",
		expires_in: 3600,
		scope,
		...extra,
	};
}

/** A token response whose ID token is signed for the issued client and this login's nonce. */
function signedResponse(clientId: string, options: IdTokenOptions = {}, scope = REQUIRED_SCOPE) {
	return async ({ loginNonce }: TokenRequest) =>
		tokenResponse(scope, { id_token: await idToken({ ...options, clientId, loginNonce }) });
}

function loginInteraction(options?: {
	callbackClientId?: string;
	onAuthorize?: (url: URL) => void;
	session?: { nonce?: string };
}): ProviderAuthInteraction {
	let authorizeUrl: URL | undefined;
	return {
		signal: neverAbortedSignal,
		notify: (event) => {
			if (event.type !== "auth_url") return;
			authorizeUrl = new URL(event.url);
			if (options?.session) options.session.nonce = authorizeUrl.searchParams.get("nonce") ?? undefined;
			options?.onAuthorize?.(authorizeUrl);
		},
		prompt: async (prompt) => {
			if (prompt.type !== "manual_code") throw new Error(`Unexpected prompt: ${prompt.type}`);
			if (!authorizeUrl) throw new Error("Authorization URL was not emitted before the callback prompt");
			const callback = new URL(authorizeUrl.searchParams.get("redirect_uri") ?? "");
			callback.searchParams.set("code", "authorization-code");
			callback.searchParams.set("state", authorizeUrl.searchParams.get("state") ?? "");
			if (options?.callbackClientId) callback.searchParams.set("client_id", options.callbackClientId);
			return callback.toString();
		},
	};
}

async function login(response: (request: TokenRequest) => unknown, extra: { expectedSubject?: string } = {}) {
	const session: { nonce?: string } = {};
	stubAuthServer(response as (request: TokenRequest) => Promise<Record<string, unknown>>, session);
	return openaiChatGPTOAuth.login(loginInteraction({ callbackClientId: "oaiapp_issued", session }), {
		getDeviceId: () => DEVICE_ID,
		...extra,
	});
}

function connectedCredential(subject: string | undefined = ACCOUNT): OAuthCredential {
	return {
		type: "oauth",
		access: "old-access",
		refresh: "old-refresh",
		expires: 0,
		clientId: "oaiapp_existing",
		scopes: REQUIRED_SCOPE.split(" "),
		...(subject ? { subject } : {}),
	};
}

// Regression coverage for https://github.com/earendil-works/pi/issues/11313.
describe("OpenAI ChatGPT OAuth", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("registers a user-owned client and stores its issued ID, granted scopes and verified account", async () => {
		let authorizeUrl: URL | undefined;
		let exchangeBody: URLSearchParams | undefined;
		const session: { nonce?: string } = {};
		stubAuthServer(async (request) => {
			exchangeBody = request.body;
			return signedResponse("oaiapp_issued")(request);
		}, session);

		const credential = await openaiChatGPTOAuth.login(
			loginInteraction({
				callbackClientId: "oaiapp_issued",
				session,
				onAuthorize: (url) => {
					authorizeUrl = url;
				},
			}),
			{ getDeviceId: () => DEVICE_ID },
		);

		expect(authorizeUrl?.searchParams.get("client_id")).toBe("dynamic_agent_client");
		expect(authorizeUrl?.searchParams.get("agent_name_hint")).toBe("Pi");
		expect(authorizeUrl?.searchParams.get("ext_agent_host_id")).toBe(`urn:uuid:${DEVICE_ID}`);
		expect(authorizeUrl?.searchParams.get("scope")).toBe(REQUIRED_SCOPE);
		expect(authorizeUrl?.searchParams.get("redirect_uri")).toBe("http://127.0.0.1:1455/auth/callback");
		expect(authorizeUrl?.searchParams.get("resource")).toBe("https://api.openai.com/v1");
		expect(authorizeUrl?.searchParams.get("code_challenge_method")).toBe("S256");
		expect(authorizeUrl?.searchParams.get("nonce")).toBeTruthy();
		expect(exchangeBody?.get("client_id")).toBe("oaiapp_issued");
		expect(exchangeBody?.get("code")).toBe("authorization-code");
		expect(exchangeBody?.get("resource")).toBe("https://api.openai.com/v1");
		expect(exchangeBody?.get("code_verifier")).toBeTruthy();
		expect(credential).toMatchObject({
			type: "oauth",
			access: "access-token",
			refresh: "refresh-token",
			clientId: "oaiapp_issued",
			scopes: REQUIRED_SCOPE.split(" "),
			subject: ACCOUNT,
		});
	});

	it("uses the app's agent name as the name hint", async () => {
		let authorizeUrl: URL | undefined;
		const session: { nonce?: string } = {};
		stubAuthServer(signedResponse("oaiapp_issued"), session);

		await openaiChatGPTOAuth.login(
			loginInteraction({
				callbackClientId: "oaiapp_issued",
				session,
				onAuthorize: (url) => {
					authorizeUrl = url;
				},
			}),
			{ getDeviceId: () => DEVICE_ID, agentName: "my-app" },
		);

		expect(authorizeUrl?.searchParams.get("agent_name_hint")).toBe("my-app");
	});

	it.each([
		["a signature from another key", { key: undefined as SigningKey | undefined, useAttacker: true }],
		["an unknown key ID", { kid: "unknown" }],
		["the wrong issuer", { issuer: "https://auth.example.com" }],
		["an audience other than the issued client", { audience: "oaiapp_other" }],
		["an expired token", { expiresAt: Math.floor(Date.now() / 1000) - 60 }],
		["the wrong nonce", { nonce: "replayed-nonce" }],
		["no nonce", { nonce: null }],
		["no subject", { subject: null }],
	])("rejects an ID token with %s", async (_label, options) => {
		const { useAttacker, ...rest } = options as IdTokenOptions & { useAttacker?: boolean };
		await expect(
			login(signedResponse("oaiapp_issued", { ...rest, ...(useAttacker ? { key: attackerKey } : {}) })),
		).rejects.toThrow("ID token failed verification");
	});

	it("rejects unsigned and symmetric-key ID tokens", async () => {
		const header = (alg: string) => Buffer.from(JSON.stringify({ alg, kid: "openai-test" })).toString("base64url");
		const claims = Buffer.from(
			JSON.stringify({
				iss: ISSUER,
				aud: "oaiapp_issued",
				sub: ACCOUNT,
				exp: Math.floor(Date.now() / 1000) + 3600,
			}),
		).toString("base64url");
		for (const forged of [`${header("none")}.${claims}.`, `${header("HS256")}.${claims}.c2lnbmF0dXJl`]) {
			await expect(login(() => tokenResponse(REQUIRED_SCOPE, { id_token: forged }))).rejects.toThrow(
				"ID token failed verification",
			);
		}
	});

	it("rejects a token response without an ID token", async () => {
		await expect(login(() => tokenResponse())).rejects.toThrow("did not contain an ID token");
	});

	it("rejects a returning sign-in that verifies as a different account", async () => {
		await expect(
			login(signedResponse("oaiapp_issued", { subject: "someone-else" }), { expectedSubject: ACCOUNT }),
		).rejects.toThrow("different ChatGPT account");
		await expect(login(signedResponse("oaiapp_issued"), { expectedSubject: ACCOUNT })).resolves.toMatchObject({
			subject: ACCOUNT,
		});
	});

	it("rejects registration without an issued client ID", async () => {
		const fetchMock = stubAuthServer(() => tokenResponse());

		await expect(openaiChatGPTOAuth.login(loginInteraction(), { getDeviceId: () => DEVICE_ID })).rejects.toThrow(
			"registration callback did not contain an issued client ID",
		);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects a token response that did not grant direct token use", async () => {
		await expect(
			login(signedResponse("oaiapp_issued", {}, "openid profile email offline_access resource.invoke")),
		).rejects.toThrow("grant did not include chatgpt.tokens.use.direct");
	});

	it("requires a device ID before starting authorization", async () => {
		let authorizationStarted = false;
		const interaction = loginInteraction({
			onAuthorize: () => {
				authorizationStarted = true;
			},
		});

		await expect(openaiChatGPTOAuth.login(interaction)).rejects.toThrow("requires a device ID");
		await expect(openaiChatGPTOAuth.login(interaction, { getDeviceId: () => "not-a-uuid" })).rejects.toThrow(
			"requires a device ID",
		);
		expect(authorizationStarted).toBe(false);
	});

	it("requires refresh responses to rotate the refresh token", async () => {
		const { refresh_token: _refreshToken, ...responseWithoutRefresh } = tokenResponse();
		stubAuthServer(() => responseWithoutRefresh);

		await expect(openaiChatGPTOAuth.refresh(connectedCredential(), neverAbortedSignal)).rejects.toThrow(
			"token response has invalid refresh_token",
		);
	});

	it("refreshes with the credential's issued client ID and stores replacement scopes", async () => {
		let refreshBody: URLSearchParams | undefined;
		stubAuthServer(({ body }) => {
			refreshBody = body;
			return { ...tokenResponse(), access_token: "new-access", refresh_token: "new-refresh" };
		});

		const before = Date.now();
		const credential = await openaiChatGPTOAuth.refresh(connectedCredential(), neverAbortedSignal);

		// expires_in is 3600 seconds; the credential expires 3 minutes early so it is refreshed in time.
		expect(credential.expires).toBeGreaterThanOrEqual(before + (3600 - 180) * 1000);
		expect(credential.expires).toBeLessThanOrEqual(Date.now() + (3600 - 180) * 1000);

		expect(refreshBody?.get("grant_type")).toBe("refresh_token");
		expect(refreshBody?.get("client_id")).toBe("oaiapp_existing");
		expect(refreshBody?.get("refresh_token")).toBe("old-refresh");
		expect(refreshBody?.get("resource")).toBe("https://api.openai.com/v1");
		expect(refreshBody?.has("scope")).toBe(false);
		expect(credential).toMatchObject({
			access: "new-access",
			refresh: "new-refresh",
			clientId: "oaiapp_existing",
			scopes: REQUIRED_SCOPE.split(" "),
			subject: ACCOUNT,
		});
	});

	it("verifies an ID token returned on refresh and keeps the account binding", async () => {
		stubAuthServer(async () =>
			tokenResponse(REQUIRED_SCOPE, {
				id_token: await idToken({ clientId: "oaiapp_existing", nonce: null, subject: "someone-else" }),
			}),
		);
		await expect(openaiChatGPTOAuth.refresh(connectedCredential(), neverAbortedSignal)).rejects.toThrow(
			"different ChatGPT account",
		);

		stubAuthServer(async () =>
			tokenResponse(REQUIRED_SCOPE, {
				id_token: await idToken({ clientId: "oaiapp_existing", nonce: null, key: attackerKey }),
			}),
		);
		await expect(openaiChatGPTOAuth.refresh(connectedCredential(), neverAbortedSignal)).rejects.toThrow(
			"ID token failed verification",
		);
	});
});
