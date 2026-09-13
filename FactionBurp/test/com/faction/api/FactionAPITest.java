package com.faction.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.nio.file.Path;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FactionAPITest {

	@TempDir
	Path dir;

	/** A client that only knows which version it was built for. */
	private static final class StubClient implements FactionClient {
		final int version;
		StubClient(int version) { this.version = version; }
		@Override public boolean isConfigured() { return true; }
		@Override public String testConnection() { return null; }
		@Override public String[] getSeverityStrings() { return new String[] { "v" + version }; }
		@Override public String getSevMapping(String b) { return "v" + version; }
		@Override public JSONArray getAssessments() { return new JSONArray(); }
		@Override public JSONObject getAssessment(String a) { return null; }
		@Override public JSONArray getAssessmentsForApplication(String a) { return new JSONArray(); }
		@Override public JSONArray getVulnerabilities(String a) { return new JSONArray(); }
		@Override public JSONObject getVulnerability(String a, String v) { return null; }
		@Override public JSONArray getRetests() { return new JSONArray(); }
		@Override public JSONArray searchDefaultVulns(String q) { return new JSONArray(); }
		@Override public JSONArray getVulnerabilityFields(String a) { return new JSONArray(); }
		@Override public JSONObject createVulnerabilityWithFields(String a, JSONObject b, Map<String, String> f) { return null; }
		@Override public JSONObject appendDetails(String a, String v, String h, String s) { return null; }
		@Override public JSONObject setSection(String a, String v, String s) { return null; }
		@Override public JSONObject setCustomFieldValues(String a, String v, Map<String, String> f) { return null; }
		@Override public String uploadInlineImage(String a, byte[] b, String f, String m) { return null; }
		@Override public byte[] getBytes(String p) { return null; }
		@Override public void clearCaches() { }
	}

	private FactionAPI api(FactionConfig cfg) {
		return new FactionAPI(cfg, StubClient::new);
	}

	private FactionConfig cfg() {
		return new FactionConfig(dir.resolve("faction.properties"));
	}

	@Test
	void selectsV2ByDefault() {
		FactionAPI api = api(cfg());
		assertEquals(2, api.getApiVersion());
		assertArrayEquals(new String[] { "v2" }, api.getSeverityStrings());
	}

	@Test
	void selectsV1WhenConfigured() {
		FactionConfig c = cfg();
		c.save(1, "http://h", "t", "20");
		FactionAPI api = api(c);
		assertEquals(1, api.getApiVersion());
		assertArrayEquals(new String[] { "v1" }, api.getSeverityStrings());
	}

	@Test
	void updatePropsPersistsAndSwapsTheClient() {
		FactionConfig c = cfg();
		FactionAPI api = api(c);
		FactionClient before = api.client();
		api.updateProps(1, "http://h:9000/", "tok", "15");
		assertEquals("v1", api.getSevMapping("high"));
		assertEquals("http://h:9000", api.getServer());
		assertEquals("tok", api.getToken());
		assertEquals(15, api.getRefresh());
		assertEquals(1, cfg().getApiVersion(), "persisted");
		// Same version again keeps the client instance (and its caches)
		FactionClient v1 = api.client();
		api.updateProps(1, "http://h:9000", "tok", "15");
		assertSame(v1, api.client());
		api.updateProps(2, "http://h:9000", "tok", "15");
		assertEquals("v2", api.getSevMapping("high"));
		assertSame(before.getClass(), api.client().getClass());
	}

	@Test
	void updateSevWritesThrough() {
		FactionConfig c = cfg();
		FactionAPI api = api(c);
		api.updateSev(FactionConfig.BURP_SEV_LOW, "informational");
		assertEquals("informational", cfg().getSeverity(FactionConfig.BURP_SEV_LOW));
	}
}
