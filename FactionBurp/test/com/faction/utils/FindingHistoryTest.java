package com.faction.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.Test;

class FindingHistoryTest {

	@SuppressWarnings("unchecked")
	private static JSONObject vuln(String id, String name, String severity, String openedAt, String closedAt) {
		JSONObject v = new JSONObject();
		v.put("id", id); v.put("name", name); v.put("severity", severity);
		if (openedAt != null) v.put("openedAt", openedAt);
		if (closedAt != null) v.put("closedAt", closedAt);
		return v;
	}

	@SuppressWarnings("unchecked")
	private static JSONArray arr(JSONObject... vs) {
		JSONArray a = new JSONArray();
		for (JSONObject v : vs) a.add(v);
		return a;
	}

	@Test
	void ownFindingsAreAllKeptEvenBeforeFinalisation() {
		List<FindingHistory.Row> rows = FindingHistory.ownRows("a1", "Current",
				arr(vuln("v1", "XSS", "HIGH", null, null), vuln("v2", "SQLi", "CRITICAL", "2026-08-01T10:00:00", null)));
		assertEquals(2, rows.size());
		assertEquals("Open", rows.get(0).status());
		assertEquals("", rows.get(0).openedAt());
		assertEquals("Current", rows.get(0).assessmentName());
		assertEquals("2026-08-01", rows.get(1).openedAt());
	}

	@Test
	void historyKeepsOnlyFinalisedFindingsNewestFirst() {
		List<FindingHistory.Row> rows = FindingHistory.siblingRows(List.of(
				new FindingHistory.Sibling("a2", "Q1 test", arr(
						vuln("v3", "Old draft", "LOW", null, null),
						vuln("v4", "Weak TLS", "MEDIUM", "2026-03-01T00:00:00", "2026-04-02T00:00:00"))),
				new FindingHistory.Sibling("a3", "Q2 test", arr(
						vuln("v5", "IDOR", "HIGH", "2026-06-01T00:00:00", null)))));
		assertEquals(2, rows.size());
		assertEquals("IDOR", rows.get(0).name());
		assertEquals("Open", rows.get(0).status());
		assertEquals("Q2 test", rows.get(0).assessmentName());
		assertEquals("Weak TLS", rows.get(1).name());
		assertEquals("Closed", rows.get(1).status());
		assertEquals("2026-04-02", rows.get(1).closedAt());
	}

	@Test
	void statusFollowsTheClosedDate() {
		assertEquals("Open", FindingHistory.status(vuln("v", "n", "LOW", "2026-01-01T00:00:00", null)));
		assertEquals("Closed", FindingHistory.status(vuln("v", "n", "LOW", "2026-01-01T00:00:00", "2026-02-01T00:00:00")));
	}
}
