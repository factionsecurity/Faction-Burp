package com.faction.api;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Client for the Faction 2.x REST API (context path /api/v1).
 *
 *  - Auth is a bearer API key: "Authorization: Bearer sk_fac_...".
 *  - All endpoints live under /api/v1 and wrap payloads in a
 *    { success, message, data, pagination } envelope; this client unwraps
 *    "data" for callers.
 *  - Request/response bodies are JSON.
 *  - Severity is a fixed enum (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL).
 */
public class FactionV2Client implements FactionClient {

	public static final String[] SEVERITIES = { "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL" };

	public static final String API_PREFIX = "/api/v1";
	public static final String ASSESSMENTS = "/assessments";
	public static final String RETESTS = "/retests";
	public static final String DEFAULT_VULNS = "/default-vulnerabilities";
	public static final String VULN_FIELDS = "/report-templates/vulnerability-fields";
	public static final String AUTH_ME = "/auth/me";

	private final Transport transport;
	private final FactionConfig config;

	private JSONArray vulnFieldsCache;

	public FactionV2Client(Transport transport, FactionConfig config) {
		this.transport = transport;
		this.config = config;
	}

	// ── Config ──────────────────────────────────────────────────────────────────

	@Override
	public boolean isConfigured() {
		String server = config.getServer();
		String token = config.getToken();
		return server != null && server.startsWith("http") && token != null && !token.trim().isEmpty();
	}

	@Override
	public String[] getSeverityStrings() {
		return SEVERITIES.clone();
	}

	@Override
	public String getSevMapping(String burpSeverity) {
		String key = burpKey(burpSeverity);
		String stored = config.getSeverity(key);
		if (stored != null && !stored.isEmpty()) return stored;
		switch (key) {
			case FactionConfig.BURP_SEV_HIGH: return "HIGH";
			case FactionConfig.BURP_SEV_MED: return "MEDIUM";
			case FactionConfig.BURP_SEV_LOW: return "LOW";
			default: return "INFORMATIONAL";
		}
	}

	/** Normalises Burp's severity spellings ("HIGH", "Information", "informational") to the config key. */
	static String burpKey(String burpSeverity) {
		if (burpSeverity == null) return FactionConfig.BURP_SEV_INFO;
		switch (burpSeverity.toLowerCase()) {
			case "high": return FactionConfig.BURP_SEV_HIGH;
			case "medium": return FactionConfig.BURP_SEV_MED;
			case "low": return FactionConfig.BURP_SEV_LOW;
			default: return FactionConfig.BURP_SEV_INFO;
		}
	}

	@Override
	public void clearCaches() {
		vulnFieldsCache = null;
	}

	// ── Endpoints ───────────────────────────────────────────────────────────────

	/**
	 * Open assessments only. {@code showCompleted=false} still returns assessments
	 * completed inside the server's reopen window, and the set of "completed"
	 * statuses is configurable per install. A completed assessment always carries
	 * a {@code completedDate}, so drop those here rather than hard-coding names.
	 */
	@Override
	public JSONArray getAssessments() {
		JSONArray all = getArray(ASSESSMENTS + "?showCompleted=false&size=200&sort=startDate,desc");
		JSONArray open = new JSONArray();
		for (Object o : all) {
			JSONObject a = (JSONObject) o;
			if (a.get("completedDate") == null) add(open, a);
		}
		return open;
	}

	@Override
	public JSONArray getAssessmentsForApplication(String applicationId) {
		if (applicationId == null || applicationId.isEmpty()) return new JSONArray();
		return getArray(ASSESSMENTS + "?applicationId=" + enc(applicationId) + "&showCompleted=true&size=200&sort=startDate,desc");
	}

	@Override
	public JSONObject getAssessment(String assessmentId) {
		return getObject(ASSESSMENTS + "/" + enc(assessmentId));
	}

	@Override
	public JSONArray getVulnerabilities(String assessmentId) {
		return getArray(ASSESSMENTS + "/" + enc(assessmentId) + "/vulnerabilities?size=500&sort=order,asc");
	}

	@Override
	public JSONObject getVulnerability(String assessmentId, String vulnId) {
		return getObject(ASSESSMENTS + "/" + enc(assessmentId) + "/vulnerabilities/" + enc(vulnId));
	}

	/** Open retests, filtered to the statuses the web UI's queue shows. */
	@Override
	public JSONArray getRetests() {
		return getArray(RETESTS + "?status=REQUESTED,SCHEDULED,IN_PROGRESS");
	}

	/** The 2.x API has no server-side search, so fetch a page and filter client-side. */
	@Override
	public JSONArray searchDefaultVulns(String query) {
		JSONArray all = getArray(DEFAULT_VULNS + "?size=500&sort=order,asc&archived=false");
		if (query == null || query.trim().isEmpty()) return all;
		String q = query.toLowerCase();
		JSONArray out = new JSONArray();
		for (Object o : all) {
			JSONObject dv = (JSONObject) o;
			if (str(dv.get("name")).toLowerCase().contains(q)) add(out, dv);
		}
		return out;
	}

	/** VULNERABILITY-scoped fields are global in 2.x; the assessment id is ignored. Cached. */
	@Override
	public JSONArray getVulnerabilityFields(String assessmentId) {
		if (vulnFieldsCache == null) vulnFieldsCache = getArray(VULN_FIELDS);
		return vulnFieldsCache;
	}

	public JSONObject createVulnerability(String assessmentId, JSONObject body) {
		return sendJson("POST", ASSESSMENTS + "/" + enc(assessmentId) + "/vulnerabilities", body);
	}

	public JSONObject patchVulnerability(String assessmentId, String vulnId, JSONObject body) {
		return sendJson("PATCH", ASSESSMENTS + "/" + enc(assessmentId) + "/vulnerabilities/" + enc(vulnId), body);
	}

	/**
	 * Creates the finding and, if custom-field values were supplied, resolves
	 * them against the created finding's field-definition snapshot ids (matched
	 * by variableName) and PATCHes them in a second call — the create endpoint
	 * validates fieldValues by snapshot id, which the client cannot know upfront.
	 */
	@Override
	public JSONObject createVulnerabilityWithFields(String assessmentId, JSONObject body, Map<String, String> valuesByVariableName) {
		JSONObject clean = new JSONObject();
		putAll(clean, body);
		clean.remove("defaultVulnerabilityId"); // 1.x-only routing hint
		JSONObject created = createVulnerability(assessmentId, clean);
		if (created == null) return null;
		if (valuesByVariableName == null || valuesByVariableName.isEmpty()) return created;

		JSONObject fieldValues = resolveFieldValues(created, valuesByVariableName);
		if (fieldValues.isEmpty()) return created;
		JSONObject patch = new JSONObject();
		put(patch, "fieldValues", fieldValues);
		JSONObject patched = patchVulnerability(assessmentId, str(created.get("id")), patch);
		return patched != null ? patched : created;
	}

	@Override
	public JSONObject appendDetails(String assessmentId, String vulnId, String html, String severity) {
		JSONObject existing = getVulnerability(assessmentId, vulnId);
		String current = existing != null ? str(existing.get("details")) : "";
		JSONObject patch = new JSONObject();
		put(patch, "details", current + html);
		return patchVulnerability(assessmentId, vulnId, patch);
	}

	@Override
	public JSONObject setSection(String assessmentId, String vulnId, String section) {
		JSONObject patch = new JSONObject();
		put(patch, "section", section);
		return patchVulnerability(assessmentId, vulnId, patch);
	}

	@Override
	public JSONObject setCustomFieldValues(String assessmentId, String vulnId, Map<String, String> valuesByVariableName) {
		if (valuesByVariableName == null || valuesByVariableName.isEmpty()) return null;
		JSONObject existing = getVulnerability(assessmentId, vulnId);
		if (existing == null) return null;
		JSONObject fieldValues = resolveFieldValues(existing, valuesByVariableName);
		if (fieldValues.isEmpty()) return existing;
		JSONObject patch = new JSONObject();
		put(patch, "fieldValues", fieldValues);
		return patchVulnerability(assessmentId, vulnId, patch);
	}

	/** Multipart upload to the assessment's inline-images endpoint; returns the short URL for an img src. */
	@Override
	public String uploadInlineImage(String assessmentId, byte[] imageBytes, String filename, String mimeType) {
		try {
			if (!isConfigured()) return null;
			String boundary = "----FactionBurpBoundary" + Long.toHexString(imageBytes.length) + "x" + System.identityHashCode(imageBytes);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			String preamble = "--" + boundary + "\r\n"
					+ "Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n"
					+ "Content-Type: " + mimeType + "\r\n\r\n";
			baos.write(preamble.getBytes(StandardCharsets.UTF_8));
			baos.write(imageBytes);
			baos.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));

			String path = ASSESSMENTS + "/" + enc(assessmentId) + "/inline-images";
			HttpRequest request = baseRequest("POST", path)
					.withAddedHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
					.withBody(ByteArray.byteArray(baos.toByteArray()));
			JSONObject data = dataObject(send(request, "POST", path));
			return data != null ? str(data.get("url")) : null;
		} catch (Exception e) {
			transport.logError("Faction: inline image upload failed: " + e);
			return null;
		}
	}

	@Override
	public String testConnection() {
		if (!isConfigured()) return "Server URL and API key are required.";
		HttpRequestResponse response = send(baseRequest("GET", AUTH_ME), "GET", AUTH_ME);
		if (response == null || !response.hasResponse()) return "No response from " + config.getServer() + ".";
		int code = response.response().statusCode();
		String body = response.response().bodyToString();
		if (code == 401 || code == 403) return "Authentication failed (HTTP " + code + "). Check the API key.";
		// A web UI / proxy answers with HTML and often a 200 — catch that here.
		if (Transport.looksLikeHtml(body)) return htmlHint(code);
		if (code == 200) {
			try {
				if (new JSONParser().parse(body) instanceof JSONObject) return null;
			} catch (Exception ignored) { }
			return "Connected, but the response was not JSON. " + htmlHint(code);
		}
		return "Unexpected response (HTTP " + code + ").";
	}

	private String htmlHint(int code) {
		return "The server returned HTML, not JSON (HTTP " + code + "). Point the extension at the "
				+ "Faction API base URL (e.g. http://localhost:8080), not the web UI or a reverse proxy.";
	}

	/** A leading {@code /api/v1} on {@code path} is tolerated, since that is how the portal writes image URLs. */
	@Override
	public byte[] getBytes(String path) {
		if (path == null) return null;
		String p = path.startsWith(API_PREFIX + "/") ? path.substring(API_PREFIX.length()) : path;
		HttpRequest request = baseRequest("GET", p).withUpdatedHeader("Accept", "*/*");
		HttpRequestResponse response = send(request, "GET", p);
		if (!Transport.isSuccess(response)) return null;
		return response.response().body().getBytes();
	}

	// ── Field-value resolution (variableName -> snapshot id) ────────────────────

	static JSONObject resolveFieldValues(JSONObject vuln, Map<String, String> valuesByVariableName) {
		JSONObject out = new JSONObject();
		Object defsObj = vuln.get("fieldDefinitions");
		if (!(defsObj instanceof JSONArray)) return out;
		for (Object o : (JSONArray) defsObj) {
			JSONObject def = (JSONObject) o;
			String variableName = str(def.get("variableName"));
			String id = str(def.get("id"));
			if (valuesByVariableName.containsKey(variableName) && !id.isEmpty()) {
				String v = valuesByVariableName.get(variableName);
				if (v != null && !v.isEmpty()) put(out, id, v);
			}
		}
		return out;
	}

	// ── Transport ───────────────────────────────────────────────────────────────

	public JSONArray getArray(String path) {
		return dataArray(send(baseRequest("GET", path), "GET", path));
	}

	public JSONObject getObject(String path) {
		return dataObject(send(baseRequest("GET", path), "GET", path));
	}

	private JSONObject sendJson(String method, String path, JSONObject body) {
		HttpRequest request = baseRequest(method, path)
				.withAddedHeader("Content-Type", "application/json")
				.withBody(body.toJSONString());
		return dataObject(send(request, method, path));
	}

	private HttpRequest baseRequest(String method, String path) {
		return transport.request(config.getServer(), method, API_PREFIX + path)
				.withAddedHeader("Authorization", "Bearer " + config.getToken());
	}

	private HttpRequestResponse send(HttpRequest request, String method, String path) {
		if (!isConfigured()) return null;
		return transport.send(request, config.getServer(), method, API_PREFIX + path);
	}

	// ── Envelope unwrapping ─────────────────────────────────────────────────────

	private JSONArray dataArray(HttpRequestResponse response) {
		JSONObject env = envelope(response);
		Object data = env == null ? null : env.get("data");
		return (data instanceof JSONArray) ? (JSONArray) data : new JSONArray();
	}

	private JSONObject dataObject(HttpRequestResponse response) {
		JSONObject env = envelope(response);
		Object data = env == null ? null : env.get("data");
		return (data instanceof JSONObject) ? (JSONObject) data : null;
	}

	private JSONObject envelope(HttpRequestResponse response) {
		if (!Transport.isSuccess(response)) return null;
		String rawBody = response.response().bodyToString();
		if (Transport.looksLikeHtml(rawBody)) {
			String first = rawBody.stripLeading();
			transport.logError("Faction: " + htmlHint(response.response().statusCode()) + " First bytes: "
					+ first.substring(0, Math.min(160, first.length())).replace("\n", " "));
			return null;
		}
		try {
			Object parsed = new JSONParser().parse(rawBody);
			return (parsed instanceof JSONObject) ? (JSONObject) parsed : null;
		} catch (Exception e) {
			transport.logError("Faction: failed to parse response body: " + e);
			return null;
		}
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	private static String enc(String s) {
		return s == null ? "" : s.replace(" ", "%20");
	}

	private static String str(Object o) {
		return o == null ? "" : o.toString();
	}

	@SuppressWarnings("unchecked")
	private static void add(JSONArray arr, Object v) { arr.add(v); }

	@SuppressWarnings("unchecked")
	private static void put(JSONObject o, String k, Object v) { o.put(k, v); }

	@SuppressWarnings("unchecked")
	private static void putAll(JSONObject target, JSONObject source) { if (source != null) target.putAll(source); }
}
