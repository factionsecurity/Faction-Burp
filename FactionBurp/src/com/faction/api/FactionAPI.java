package com.faction.api;

import java.util.Map;
import java.util.function.Function;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import burp.api.montoya.MontoyaApi;

/**
 * The GUI's single entry point to Faction. Owns the {@link FactionConfig} and
 * delegates every call to the {@link FactionClient} that matches the configured
 * API generation — {@link FactionV1Client} for Faction 1.x, {@link FactionV2Client}
 * for 2.x. Saving a new version in the Config tab swaps the client in place, so
 * the rest of the extension never needs to know which server it is talking to.
 */
public class FactionAPI implements FactionClient {

	public static final String BURP_SEV_HIGH = FactionConfig.BURP_SEV_HIGH;
	public static final String BURP_SEV_MED = FactionConfig.BURP_SEV_MED;
	public static final String BURP_SEV_LOW = FactionConfig.BURP_SEV_LOW;
	public static final String BURP_SEV_INFO = FactionConfig.BURP_SEV_INFO;

	public static final int VERSION_1 = 1;
	public static final int VERSION_2 = 2;

	private final FactionConfig config;
	private final Function<Integer, FactionClient> factory;
	private FactionClient client;
	private int clientVersion;

	public FactionAPI(MontoyaApi api) {
		this(FactionConfig.defaultLocation(), clientFactory(new Transport(api), FactionConfig.defaultLocation()));
	}

	/** Test constructor: {@code factory} builds a client for a version number. */
	FactionAPI(FactionConfig config, Function<Integer, FactionClient> factory) {
		this.config = config;
		this.factory = factory;
		rebuildClient();
	}

	private static Function<Integer, FactionClient> clientFactory(Transport transport, FactionConfig config) {
		return version -> version == VERSION_1 ? new FactionV1Client(transport, config) : new FactionV2Client(transport, config);
	}

	private synchronized void rebuildClient() {
		int version = config.getApiVersion();
		if (client != null && version == clientVersion) return;
		client = factory.apply(version);
		clientVersion = version;
	}

	synchronized FactionClient client() {
		return client;
	}

	// ── Config ──────────────────────────────────────────────────────────────────

	public FactionConfig config() { return config; }
	public int getApiVersion() { return config.getApiVersion(); }
	public String getServer() { return config.getServer(); }
	public String getToken() { return config.getToken(); }
	public int getRefresh() { return config.getRefresh(); }

	/** Persists the connection settings and switches client if the version changed. */
	public void updateProps(int apiVersion, String server, String token, String refresh) {
		config.save(apiVersion, server, token, refresh);
		rebuildClient();
	}

	public void updateSev(String burpKey, String factionSeverity) {
		config.saveSeverity(burpKey, factionSeverity);
	}

	// ── Delegation ──────────────────────────────────────────────────────────────

	@Override public boolean isConfigured() { return client().isConfigured(); }
	@Override public String testConnection() { return client().testConnection(); }
	@Override public String[] getSeverityStrings() { return client().getSeverityStrings(); }
	@Override public String getSevMapping(String burpSeverity) { return client().getSevMapping(burpSeverity); }
	@Override public JSONArray getAssessments() { return client().getAssessments(); }
	@Override public JSONObject getAssessment(String assessmentId) { return client().getAssessment(assessmentId); }
	@Override public JSONArray getAssessmentsForApplication(String applicationId) { return client().getAssessmentsForApplication(applicationId); }
	@Override public JSONArray getVulnerabilities(String assessmentId) { return client().getVulnerabilities(assessmentId); }
	@Override public JSONObject getVulnerability(String assessmentId, String vulnId) { return client().getVulnerability(assessmentId, vulnId); }
	@Override public JSONArray getRetests() { return client().getRetests(); }
	@Override public JSONArray searchDefaultVulns(String query) { return client().searchDefaultVulns(query); }
	@Override public JSONArray getVulnerabilityFields(String assessmentId) { return client().getVulnerabilityFields(assessmentId); }
	@Override public JSONObject createVulnerabilityWithFields(String assessmentId, JSONObject body, Map<String, String> fieldValues) { return client().createVulnerabilityWithFields(assessmentId, body, fieldValues); }
	@Override public JSONObject appendDetails(String assessmentId, String vulnId, String html, String severity) { return client().appendDetails(assessmentId, vulnId, html, severity); }
	@Override public JSONObject setSection(String assessmentId, String vulnId, String section) { return client().setSection(assessmentId, vulnId, section); }
	@Override public JSONObject setCustomFieldValues(String assessmentId, String vulnId, Map<String, String> values) { return client().setCustomFieldValues(assessmentId, vulnId, values); }
	@Override public String uploadInlineImage(String assessmentId, byte[] imageBytes, String filename, String mimeType) { return client().uploadInlineImage(assessmentId, imageBytes, filename, mimeType); }
	@Override public byte[] getBytes(String path) { return client().getBytes(path); }
	@Override public void clearCaches() { client().clearCaches(); }
}
