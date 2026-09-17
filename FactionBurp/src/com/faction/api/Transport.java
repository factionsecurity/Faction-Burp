package com.faction.api;

import java.net.URL;
import java.util.concurrent.CompletableFuture;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;

/**
 * The HTTP plumbing both API clients share: building a Montoya request against
 * the configured server URL, sending it through Burp, and logging failures with
 * enough context to debug them (URL, status, body, request).
 */
public final class Transport {

	private final Http http;
	private final Logging logging;

	public Transport(MontoyaApi api) {
		this.http = api.http();
		this.logging = api.logging();
	}

	/** A request to {@code server}'s context path + {@code path}, with Host and Accept set. */
	public HttpRequest request(String server, String method, String path) {
		return HttpRequest.httpRequest()
				.withService(service(server))
				.withHeader("Host", hostHeader(server))
				.withMethod(method)
				.withPath(contextPath(server) + path)
				.withAddedHeader("Accept", "application/json");
	}

	/**
	 * Sends the request through Burp. Returns the response (even a non-2xx one,
	 * so callers can inspect it) or null when sending threw. Non-2xx responses and
	 * exceptions are logged.
	 */
	public HttpRequestResponse send(HttpRequest request, String server, String method, String path) {
		try {
			CompletableFuture<HttpRequestResponse> future = CompletableFuture.supplyAsync(() -> http.sendRequest(request));
			HttpRequestResponse response = future.get();
			if (!isSuccess(response)) logFailure(server, method, path, request, response, null);
			return response;
		} catch (Exception e) {
			logFailure(server, method, path, request, null, e);
			return null;
		}
	}

	public static boolean isSuccess(HttpRequestResponse response) {
		if (response == null || !response.hasResponse()) return false;
		int code = response.response().statusCode();
		return code >= 200 && code < 300;
	}

	public static boolean looksLikeHtml(String body) {
		return body != null && body.stripLeading().startsWith("<");
	}

	public void logError(String message) {
		logging.logToError(message);
	}

	public void logOutput(String message) {
		logging.logToOutput(message);
	}

	private void logFailure(String server, String method, String path, HttpRequest request, HttpRequestResponse response, Throwable error) {
		StringBuilder sb = new StringBuilder("Faction API request failed");
		sb.append("\n  URL: ").append(method).append(" ").append(server == null ? "" : server).append(path);
		if (response != null && response.hasResponse()) {
			sb.append("\n  Status: ").append(response.response().statusCode());
			sb.append("\n  Response: ").append(response.response().bodyToString());
		} else {
			sb.append("\n  Status: no response from server");
		}
		if (error != null) sb.append("\n  Error: ").append(error);
		if (request != null) sb.append("\n  Request:\n").append(request.toString());
		logging.logToError(sb.toString());
	}

	// ── URL helpers ─────────────────────────────────────────────────────────────

	static HttpService service(String server) {
		try {
			URL url = new URL(server);
			boolean secure = "https".equals(url.getProtocol());
			int port = url.getPort();
			if (port == -1) port = secure ? 443 : 80;
			return HttpService.httpService(url.getHost(), port, secure);
		} catch (Exception e) {
			return HttpService.httpService("localhost", 8080, false);
		}
	}

	static String hostHeader(String server) {
		try {
			URL url = new URL(server);
			int port = url.getPort();
			boolean secure = "https".equals(url.getProtocol());
			if (port == -1 || (secure && port == 443) || (!secure && port == 80)) return url.getHost();
			return url.getHost() + ":" + port;
		} catch (Exception e) {
			return "localhost";
		}
	}

	/** The path component of the server URL without a trailing slash ("" when none). */
	static String contextPath(String server) {
		try {
			String p = new URL(server).getPath();
			if (p == null) return "";
			while (p.endsWith("/")) p = p.substring(0, p.length() - 1);
			return p;
		} catch (Exception e) {
			return "";
		}
	}
}
