package com.faction.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FactionV2ClientTest {

	@TempDir
	Path dir;

	/** Records each GET path and answers with a canned list instead of sending anything. */
	private static final class RecordingClient extends FactionV2Client {
		final List<String> paths = new ArrayList<>();
		JSONArray response = new JSONArray();
		RecordingClient(FactionConfig config) { super(null, config); }
		@Override public JSONArray getArray(String path) { paths.add(path); return response; }
	}

	@SuppressWarnings("unchecked")
	private static JSONObject assessment(String id, Object completedDate) {
		JSONObject a = new JSONObject();
		a.put("id", id);
		a.put("completedDate", completedDate);
		return a;
	}

	@Test
	void assessmentsAreLimitedToTheSignedInUser() {
		RecordingClient client = new RecordingClient(new FactionConfig(dir.resolve("faction.properties")));
		client.getAssessments();
		assertEquals(1, client.paths.size());
		assertTrue(client.paths.get(0).contains("assignedToMe=true"), client.paths.get(0));
		assertTrue(client.paths.get(0).contains("showCompleted=false"), client.paths.get(0));
	}

	@Test
	@SuppressWarnings("unchecked")
	void completedAssessmentsAreDropped() {
		RecordingClient client = new RecordingClient(new FactionConfig(dir.resolve("faction.properties")));
		client.response.add(assessment("open", null));
		client.response.add(assessment("done", "2026-10-01T00:00:00"));
		JSONArray result = client.getAssessments();
		assertEquals(1, result.size());
		assertEquals("open", ((JSONObject) result.get(0)).get("id"));
	}
}
