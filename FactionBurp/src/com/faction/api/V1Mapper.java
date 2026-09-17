package com.faction.api;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

/**
 * Pure translations from the Faction 1.x JSON shapes (PascalCase keys, epoch
 * millisecond dates, numeric risk levels) into the 2.x shapes the GUI reads.
 * No I/O; everything here is unit-tested in isolation.
 */
public final class V1Mapper {

	private static final DateTimeFormatter ISO_DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd");
	private static final Pattern MARKDOWN_LINK = Pattern.compile("\\]\\(([^)]+)\\)");

	private V1Mapper() { }

	/** Epoch milliseconds (as a number or numeric string) → {@code yyyy-MM-dd}; "" for null or garbage. */
	public static String isoDate(Object epochMillis) {
		if (epochMillis == null) return "";
		try {
			long ms = epochMillis instanceof Number ? ((Number) epochMillis).longValue() : Long.parseLong(epochMillis.toString().trim());
			return ISO_DATE.format(Instant.ofEpochMilli(ms).atZone(ZoneId.systemDefault()));
		} catch (Exception e) {
			return "";
		}
	}

	/** Queue row → 2.x AssessmentDto. {@code sections} are the server's global report sections. */
	public static JSONObject assessment(JSONObject v1, JSONArray sections) {
		JSONObject a = new JSONObject();
		put(a, "id", str(v1.get("Id")));
		put(a, "appId", str(v1.get("AppId")));
		put(a, "name", str(v1.get("Name")));
		put(a, "applicationName", "");
		put(a, "applicationId", "");
		put(a, "status", "Open");
		put(a, "startDate", isoDate(v1.get("Start")));
		put(a, "plannedEndDate", isoDate(v1.get("End")));
		put(a, "scope", scopeHtml(v1.get("AccessNotes"), v1.get("Notes")));
		put(a, "sections", sections == null ? new JSONArray() : sections);
		return a;
	}

	/** The 1.x access notes and notes, as one HTML block for the scope pane. */
	public static String scopeHtml(Object accessNotes, Object notes) {
		String creds = str(accessNotes).trim();
		String body = str(notes).trim();
		StringBuilder sb = new StringBuilder();
		if (!creds.isEmpty()) sb.append("<h4>Access Notes</h4>").append(creds);
		if (!body.isEmpty()) {
			if (sb.length() > 0) sb.append("<h4>Notes</h4>");
			sb.append(body);
		}
		return sb.toString();
	}

	/** Vulnerability (list row or full record) → 2.x VulnerabilityDto. */
	public static JSONObject vulnerability(JSONObject v1) {
		JSONObject v = new JSONObject();
		put(v, "id", str(v1.get("Id")));
		put(v, "name", str(v1.get("Name")));
		put(v, "severity", str(v1.get("OverallStr")));
		put(v, "impact", str(v1.get("ImpactStr")));
		put(v, "likelihood", str(v1.get("LikelyhoodStr")));
		putDate(v, "openedAt", v1.get("Opened"));
		putDate(v, "closedAt", v1.get("Closed"));
		put(v, "description", str(v1.get("Description")));
		put(v, "recommendation", str(v1.get("Recommendation")));
		put(v, "details", str(v1.get("Details")));
		put(v, "section", str(v1.get("Section")));
		JSONObject fieldValues = new JSONObject();
		Object cfs = v1.get("CustomFields");
		if (cfs instanceof JSONArray) {
			for (Object o : (JSONArray) cfs) {
				if (!(o instanceof JSONObject)) continue;
				JSONObject cf = (JSONObject) o;
				String key = str(cf.get("Key"));
				if (!key.isEmpty()) put(fieldValues, key, str(cf.get("Value")));
			}
		}
		put(v, "fieldValues", fieldValues);
		return v;
	}

	/** Verification-queue row → 2.x RetestDto. 1.x rows carry no assessment id. */
	public static JSONObject retest(JSONObject v1) {
		JSONObject r = new JSONObject();
		put(r, "scheduledStartDate", isoDate(v1.get("Start")));
		put(r, "assessmentName", str(v1.get("AssessmentName")));
		put(r, "vulnerabilityName", str(v1.get("Name")));
		put(r, "vulnerabilitySeverity", str(v1.get("OverallStr")));
		put(r, "vulnerabilityId", str(v1.get("Id")));
		put(r, "assessmentId", "");
		put(r, "status", "REQUESTED");
		return r;
	}

	/**
	 * Default-vulnerability template → 2.x DefaultVulnerabilityDto. {@code Overall}
	 * is a risk-level id; it becomes the level's name via {@code levelNamesById}
	 * and is omitted when unknown. {@code defaultVulnerabilityId} lets the v1
	 * client route the create to {@code addDefaultVuln}.
	 */
	public static JSONObject defaultVuln(JSONObject v1, Map<Integer, String> levelNamesById) {
		JSONObject dv = new JSONObject();
		String id = str(v1.get("Id"));
		put(dv, "id", id);
		put(dv, "defaultVulnerabilityId", id);
		put(dv, "name", str(v1.get("Name")));
		Object overall = v1.get("Overall");
		if (overall instanceof Number && levelNamesById != null) {
			String name = levelNamesById.get(((Number) overall).intValue());
			if (name != null) put(dv, "severity", name);
		}
		if (v1.get("Description") != null) put(dv, "description", str(v1.get("Description")));
		if (v1.get("Recommendation") != null) put(dv, "recommendation", str(v1.get("Recommendation")));
		return dv;
	}

	/**
	 * Custom-field definition → 2.x shape. 1.x keys fields by their display
	 * {@code Key}, so that becomes both variableName and displayName. {@code List}
	 * fields hold their comma-separated options in {@code DefaultValue}. Boolean
	 * fields are dropped (the original extension skipped them too) → null.
	 */
	public static JSONObject customField(JSONObject v1) {
		if (v1 == null) return null;
		String key = str(v1.get("Key"));
		if (key.isEmpty()) return null;
		String type = str(v1.get("FieldType"));
		if (type.equalsIgnoreCase("Boolean")) return null;

		JSONObject f = new JSONObject();
		put(f, "variableName", key);
		put(f, "displayName", key);
		put(f, "readOnly", Boolean.TRUE.equals(v1.get("Readonly")));
		String defaultValue = str(v1.get("DefaultValue"));
		if (type.equalsIgnoreCase("List")) {
			put(f, "fieldType", "DROPDOWN");
			JSONArray options = new JSONArray();
			for (String opt : defaultValue.split(",")) {
				String t = opt.trim();
				if (!t.isEmpty()) add(options, t);
			}
			put(f, "dropdownOptions", options);
			put(f, "defaultValue", "");
		} else if (type.equalsIgnoreCase("Rich Text")) {
			put(f, "fieldType", "RICH_TEXT");
			put(f, "defaultValue", defaultValue);
		} else {
			put(f, "fieldType", "STRING");
			put(f, "defaultValue", defaultValue);
		}
		return f;
	}

	public static JSONArray customFields(JSONArray v1) {
		JSONArray out = new JSONArray();
		if (v1 == null) return out;
		for (Object o : v1) {
			JSONObject f = o instanceof JSONObject ? customField((JSONObject) o) : null;
			if (f != null) add(out, f);
		}
		return out;
	}

	/**
	 * The image URL from a 1.x image-upload response. The response holds a
	 * markdown link ({@code ![x](url)}) under a key the API never pinned down, so
	 * every value is inspected; a bare URL under {@code url} is accepted too.
	 */
	public static String markdownImageUrl(JSONObject response) {
		if (response == null) return null;
		for (Object v : response.values()) {
			if (v == null) continue;
			Matcher m = MARKDOWN_LINK.matcher(v.toString());
			if (m.find()) return m.group(1).trim();
		}
		Object url = response.get("url");
		return url == null || url.toString().isEmpty() ? null : url.toString();
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	private static void putDate(JSONObject o, String key, Object epoch) {
		String iso = isoDate(epoch);
		if (!iso.isEmpty()) put(o, key, iso);
	}

	static String str(Object o) {
		return o == null ? "" : o.toString();
	}

	@SuppressWarnings("unchecked")
	private static void put(JSONObject o, String k, Object v) { o.put(k, v); }

	@SuppressWarnings("unchecked")
	private static void add(JSONArray a, Object v) { a.add(v); }
}
