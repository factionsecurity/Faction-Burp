package com.faction.api;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Client for the original Faction 1.x API.
 *
 *  - Auth is the {@code FACTION-API-KEY} header.
 *  - Endpoints hang directly off the server's context path and return bare
 *    JSON arrays/objects (no envelope).
 *  - Writes are form-urlencoded; HTML fields are base64-encoded.
 *  - Severities are server-defined risk levels ({@code /vulnerabilities/getrisklevels/}),
 *    identified by numeric id; the GUI sees their names.
 *
 * Every response is translated to the 2.x shape by {@link V1Mapper}.
 */
public class FactionV1Client implements FactionClient {

	public static final String ADD_VULN = "/assessments/addVuln/";
	public static final String ADD_DEFAULT_VULN = "/assessments/addDefaultVuln/";
	public static final String SEARCH_DEFAULT_VULN = "/vulnerabilities/default/";
	public static final String QUEUE = "/assessments/queue";
	public static final String VERIFICATION_QUEUE = "/verifications/queue";
	public static final String GET_VULN = "/assessments/vuln/";
	public static final String GET_VULNS = "/assessments/vulns/";
	public static final String CUSTOM_FIELDS = "/assessments/customfields/";
	public static final String IMAGE = "/assessments/image/";
	public static final String REPORT_SECTIONS = "/assessments/report-sections";
	public static final String LEVELS = "/vulnerabilities/getrisklevels/";

	private final Transport transport;
	private final FactionConfig config;

	// Session caches — static per server; clearCaches() drops them.
	private LinkedHashMap<String, Integer> levelIdsByName;
	private JSONArray sectionsCache;
	private final Map<String, JSONArray> customFieldsCache = new HashMap<>();
	private JSONArray lastQueue; // raw 1.x queue, for getAssessment()

	public FactionV1Client(Transport transport, FactionConfig config) {
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

	/** Risk-level names, in server order. Empty until the server answers. */
	@Override
	public String[] getSeverityStrings() {
		return levelMap().keySet().toArray(new String[0]);
	}

	/**
	 * The configured Faction level name for a Burp severity. A numeric stored
	 * value — what the 1.x extension wrote — is resolved through the level map.
	 * Falls back to the old extension's default ids (4/3/2/0).
	 */
	@Override
	public String getSevMapping(String burpSeverity) {
		String key = FactionV2Client.burpKey(burpSeverity);
		String stored = config.getSeverity(key);
		if (stored == null || stored.isEmpty()) stored = "" + defaultLevelId(key);
		Integer asId = parseInt(stored);
		if (asId == null) return stored; // already a name
		String name = levelNameById(asId);
		return name != null ? name : stored;
	}

	private static int defaultLevelId(String burpKey) {
		switch (burpKey) {
			case FactionConfig.BURP_SEV_HIGH: return 4;
			case FactionConfig.BURP_SEV_MED: return 3;
			case FactionConfig.BURP_SEV_LOW: return 2;
			default: return 0;
		}
	}

	@Override
	public void clearCaches() {
		levelIdsByName = null;
		sectionsCache = null;
		customFieldsCache.clear();
		lastQueue = null;
	}

	// ── Severity levels ─────────────────────────────────────────────────────────

	private synchronized LinkedHashMap<String, Integer> levelMap() {
		if (levelIdsByName != null && !levelIdsByName.isEmpty()) return levelIdsByName;
		LinkedHashMap<String, Integer> map = new LinkedHashMap<>();
		for (Object o : getArray(LEVELS)) {
			if (!(o instanceof JSONObject)) continue;
			JSONObject level = (JSONObject) o;
			String name = V1Mapper.str(level.get("name")).toLowerCase();
			Object id = level.get("id");
			if (name.isEmpty() || !(id instanceof Number)) continue;
			map.put(name, ((Number) id).intValue());
		}
		levelIdsByName = map;
		return map;
	}

	private Map<Integer, String> levelNamesById() {
		Map<Integer, String> out = new HashMap<>();
		for (Map.Entry<String, Integer> e : levelMap().entrySet()) out.put(e.getValue(), e.getKey());
		return out;
	}

	private String levelNameById(int id) {
		return levelNamesById().get(id);
	}

	/** The level id for a level name (case-insensitive); null when unknown. */
	Integer levelId(String name) {
		if (name == null) return null;
		Integer id = levelMap().get(name.toLowerCase());
		if (id != null) return id;
		return parseInt(name); // tolerate a numeric id being passed straight through
	}

	// ── Assessments ─────────────────────────────────────────────────────────────

	@Override
	public JSONArray getAssessments() {
		JSONArray queue = getArray(QUEUE);
		lastQueue = queue;
		JSONArray sections = sections();
		JSONArray out = new JSONArray();
		for (Object o : queue) if (o instanceof JSONObject) add(out, V1Mapper.assessment((JSONObject) o, sections));
		return out;
	}

	/** 1.x has no single-assessment endpoint; the queue row is used. */
	@Override
	public JSONObject getAssessment(String assessmentId) {
		if (assessmentId == null || assessmentId.isEmpty()) return null;
		JSONArray queue = lastQueue != null ? lastQueue : getArray(QUEUE);
		for (Object o : queue) {
			if (o instanceof JSONObject && assessmentId.equals(V1Mapper.str(((JSONObject) o).get("Id")))) {
				return V1Mapper.assessment((JSONObject) o, sections());
			}
		}
		return null;
	}

	/** Not available in 1.x. */
	@Override
	public JSONArray getAssessmentsForApplication(String applicationId) {
		return new JSONArray();
	}

	private synchronized JSONArray sections() {
		if (sectionsCache == null) sectionsCache = getArray(REPORT_SECTIONS);
		return sectionsCache;
	}

	// ── Vulnerabilities ─────────────────────────────────────────────────────────

	@Override
	public JSONArray getVulnerabilities(String assessmentId) {
		JSONArray out = new JSONArray();
		for (Object o : getArray(GET_VULNS + enc(assessmentId))) if (o instanceof JSONObject) add(out, V1Mapper.vulnerability((JSONObject) o));
		return out;
	}

	@Override
	public JSONObject getVulnerability(String assessmentId, String vulnId) {
		JSONObject v = getObject(GET_VULN + enc(vulnId));
		return v == null ? null : V1Mapper.vulnerability(v);
	}

	@Override
	public JSONArray getRetests() {
		JSONArray out = new JSONArray();
		for (Object o : getArray(VERIFICATION_QUEUE)) if (o instanceof JSONObject) add(out, V1Mapper.retest((JSONObject) o));
		return out;
	}

	@Override
	public JSONArray searchDefaultVulns(String query) {
		if (query == null || query.trim().isEmpty()) return new JSONArray();
		Map<Integer, String> names = levelNamesById();
		JSONArray out = new JSONArray();
		for (Object o : getArray(SEARCH_DEFAULT_VULN + enc(query.trim()))) if (o instanceof JSONObject) add(out, V1Mapper.defaultVuln((JSONObject) o, names));
		return out;
	}

	@Override
	public JSONArray getVulnerabilityFields(String assessmentId) {
		if (assessmentId == null || assessmentId.isEmpty()) return new JSONArray();
		JSONArray cached = customFieldsCache.get(assessmentId);
		if (cached != null) return cached;
		JSONObject resp = getObject(CUSTOM_FIELDS + enc(assessmentId));
		Object fields = resp == null ? null : resp.get("vulnerabilityFields");
		JSONArray mapped = V1Mapper.customFields(fields instanceof JSONArray ? (JSONArray) fields : null);
		customFieldsCache.put(assessmentId, mapped);
		return mapped;
	}

	/**
	 * One form POST carries name, details, description, recommendation, severity,
	 * custom fields and section. When the GUI picked a default vulnerability the
	 * {@code addDefaultVuln} endpoint is used so the server copies the template.
	 */
	@Override
	public JSONObject createVulnerabilityWithFields(String assessmentId, JSONObject body, Map<String, String> fieldValuesByVariableName) {
		Integer severityId = levelId(V1Mapper.str(body.get("severity")));
		String section = V1Mapper.str(body.get("section"));
		String form = V1Forms.createVuln(body, severityId, fieldValuesByVariableName, section);
		String dvId = V1Mapper.str(body.get("defaultVulnerabilityId"));
		String path = dvId.isEmpty() ? ADD_VULN + enc(assessmentId) : ADD_DEFAULT_VULN + enc(assessmentId) + "/" + enc(dvId);
		return postForm(path, form) ? okResult() : null;
	}

	@Override
	public JSONObject appendDetails(String assessmentId, String vulnId, String html, String severity) {
		String form = V1Forms.appendDetails(html, levelId(severity));
		return postForm(ADD_VULN + enc(assessmentId) + "/" + enc(vulnId), form) ? okResult() : null;
	}

	@Override
	public JSONObject setSection(String assessmentId, String vulnId, String section) {
		return postForm(GET_VULN + enc(vulnId), V1Forms.section(section)) ? okResult() : null;
	}

	@Override
	public JSONObject setCustomFieldValues(String assessmentId, String vulnId, Map<String, String> valuesByVariableName) {
		if (valuesByVariableName == null || valuesByVariableName.isEmpty()) return null;
		return postForm(GET_VULN + enc(vulnId) + "/customfields", V1Forms.customFields(valuesByVariableName)) ? okResult() : null;
	}

	@Override
	public String uploadInlineImage(String assessmentId, byte[] imageBytes, String filename, String mimeType) {
		HttpRequestResponse response = send(formRequest(IMAGE + enc(assessmentId), V1Forms.image(imageBytes, mimeType)), "POST", IMAGE + assessmentId);
		return V1Mapper.markdownImageUrl(parseObject(response));
	}

	@Override
	public String testConnection() {
		if (!isConfigured()) return "Server URL and API key are required.";
		HttpRequestResponse response = send(baseRequest("GET", LEVELS), "GET", LEVELS);
		if (response == null || !response.hasResponse()) return "No response from " + config.getServer() + ".";
		int code = response.response().statusCode();
		String body = response.response().bodyToString();
		if (code == 401 || code == 403) return "Authentication failed (HTTP " + code + "). Check the API key.";
		if (Transport.looksLikeHtml(body)) return htmlHint(code);
		if (code == 200) {
			try {
				if (new JSONParser().parse(body) instanceof JSONArray) return null;
			} catch (Exception ignored) { }
			return "Connected, but the response was not the expected JSON. " + htmlHint(code);
		}
		return "Unexpected response (HTTP " + code + ").";
	}

	private String htmlHint(int code) {
		return "The server returned HTML, not JSON (HTTP " + code + "). Point the extension at the Faction "
				+ "base URL (e.g. https://faction.example.com), and check that Faction 1.x is selected.";
	}

	@Override
	public byte[] getBytes(String path) {
		if (path == null || path.isEmpty()) return null;
		HttpRequest request = baseRequest("GET", path).withUpdatedHeader("Accept", "*/*");
		HttpRequestResponse response = send(request, "GET", path);
		if (!Transport.isSuccess(response)) return null;
		return response.response().body().getBytes();
	}

	// ── Transport ───────────────────────────────────────────────────────────────

	private JSONArray getArray(String path) {
		HttpRequestResponse response = send(baseRequest("GET", path), "GET", path);
		Object parsed = parse(response);
		return parsed instanceof JSONArray ? (JSONArray) parsed : new JSONArray();
	}

	private JSONObject getObject(String path) {
		return parseObject(send(baseRequest("GET", path), "GET", path));
	}

	private boolean postForm(String path, String form) {
		return Transport.isSuccess(send(formRequest(path, form), "POST", path));
	}

	private HttpRequest formRequest(String path, String form) {
		return baseRequest("POST", path)
				.withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
				.withBody(form);
	}

	private HttpRequest baseRequest(String method, String path) {
		return transport.request(config.getServer(), method, path)
				.withAddedHeader("FACTION-API-KEY", config.getToken())
				.withAddedHeader("Content-Language", "en-US");
	}

	private HttpRequestResponse send(HttpRequest request, String method, String path) {
		if (!isConfigured()) return null;
		return transport.send(request, config.getServer(), method, path);
	}

	private JSONObject parseObject(HttpRequestResponse response) {
		Object parsed = parse(response);
		return parsed instanceof JSONObject ? (JSONObject) parsed : null;
	}

	private Object parse(HttpRequestResponse response) {
		if (!Transport.isSuccess(response)) return null;
		String body = response.response().bodyToString();
		if (Transport.looksLikeHtml(body)) {
			transport.logError("Faction: " + htmlHint(response.response().statusCode()));
			return null;
		}
		try {
			return new JSONParser().parse(body);
		} catch (Exception e) {
			transport.logError("Faction: failed to parse response body: " + e);
			return null;
		}
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	/** 1.x write endpoints return an empty array; give callers a non-null marker. */
	private static JSONObject okResult() {
		JSONObject o = new JSONObject();
		put(o, "success", Boolean.TRUE);
		return o;
	}

	/** The original client only replaced spaces (as "+") with %20; keep that. */
	private static String enc(String s) {
		return s == null ? "" : s.replace(" ", "%20").replace("+", "%20");
	}

	private static Integer parseInt(String s) {
		try { return Integer.valueOf(s.trim()); } catch (Exception e) { return null; }
	}

	@SuppressWarnings("unchecked")
	private static void add(JSONArray a, Object v) { a.add(v); }

	@SuppressWarnings("unchecked")
	private static void put(JSONObject o, String k, Object v) { o.put(k, v); }
}
