package com.faction.utils;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

/**
 * Rows for the Assessment tab's findings table: the selected assessment's own
 * findings plus the application's history — findings from its other
 * assessments that have been finalised (they carry an opened date), each
 * shown as Open or Closed. Mirrors the portal's Assessment History section.
 */
public final class FindingHistory {

	public record Row(String assessmentId, String assessmentName, String vulnId, String name,
			String severity, String status, String openedAt, String closedAt) { }

	/** Another assessment of the same application, with its findings. */
	public record Sibling(String assessmentId, String assessmentName, JSONArray findings) { }

	private FindingHistory() { }

	/** Every finding of the selected assessment, finalised or not — it is the work in progress. */
	public static List<Row> ownRows(String assessmentId, String assessmentName, JSONArray findings) {
		List<Row> out = new ArrayList<>();
		if (findings == null) return out;
		for (Object o : findings) out.add(row(assessmentId, assessmentName, (JSONObject) o));
		return out;
	}

	/** Finalised findings from the application's other assessments, newest opened first. */
	public static List<Row> siblingRows(List<Sibling> siblings) {
		List<Row> out = new ArrayList<>();
		if (siblings == null) return out;
		for (Sibling s : siblings) {
			if (s.findings() == null) continue;
			for (Object o : s.findings()) {
				JSONObject v = (JSONObject) o;
				if (v.get("openedAt") == null) continue;
				out.add(row(s.assessmentId(), s.assessmentName(), v));
			}
		}
		out.sort(Comparator.comparing(Row::openedAt, Comparator.reverseOrder()).thenComparing(Row::name));
		return out;
	}

	/** "Closed" once a finding has a closed date, otherwise "Open" — as the portal shows it. */
	public static String status(JSONObject v) {
		Object closed = v.get("closedAt");
		return closed != null && !closed.toString().isEmpty() ? "Closed" : "Open";
	}

	/** The date portion of an ISO date-time ("2026-07-22T10:00" → "2026-07-22"); "" for null. */
	public static String datePart(Object iso) {
		if (iso == null) return "";
		String s = iso.toString();
		int t = s.indexOf('T');
		return t > 0 ? s.substring(0, t) : s;
	}

	private static Row row(String assessmentId, String assessmentName, JSONObject v) {
		return new Row(assessmentId, assessmentName, str(v.get("id")), str(v.get("name")),
				str(v.get("severity")), status(v), datePart(v.get("openedAt")), datePart(v.get("closedAt")));
	}

	private static String str(Object o) {
		return o == null ? "" : o.toString();
	}
}
