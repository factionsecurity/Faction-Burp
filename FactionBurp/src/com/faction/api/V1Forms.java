package com.faction.api;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.json.simple.JSONObject;

/**
 * Builders for the {@code application/x-www-form-urlencoded} bodies the Faction
 * 1.x API expects. HTML fields (details, description, recommendation) travel
 * base64-encoded, then URL-encoded, exactly as the original extension sent them.
 */
public final class V1Forms {

	private V1Forms() { }

	/**
	 * Body for {@code /assessments/addVuln/{aid}} and {@code /assessments/addDefaultVuln/{aid}/{dvId}}.
	 * {@code body} is the 2.x create shape; {@code severityId} is the resolved risk-level id (omitted when null).
	 */
	public static String createVuln(JSONObject body, Integer severityId, Map<String, String> customFields, String section) {
		StringBuilder sb = new StringBuilder();
		sb.append("name=").append(enc(str(body.get("name"))));
		sb.append("&feed=false");
		appendB64(sb, "details", body.get("details"));
		appendB64(sb, "description", body.get("description"));
		appendB64(sb, "recommendation", body.get("recommendation"));
		if (severityId != null) sb.append("&severity=").append(severityId);
		if (customFields != null && !customFields.isEmpty()) sb.append('&').append(customFields(customFields));
		if (section != null && !section.isEmpty()) sb.append('&').append(section(section));
		return sb.toString();
	}

	/** Body for {@code /assessments/addVuln/{aid}/{vid}} — the server appends the details. */
	public static String appendDetails(String html, Integer severityId) {
		StringBuilder sb = new StringBuilder("feed=false&details=").append(enc(b64(html == null ? "" : html)));
		if (severityId != null) sb.append("&severity=").append(severityId);
		return sb.toString();
	}

	/** Body for {@code /assessments/vuln/{vid}}. */
	public static String section(String section) {
		return "section=" + enc(section == null ? "" : section);
	}

	/** Body for {@code /assessments/vuln/{vid}/customfields}: a JSON object keyed by field Key. */
	public static String customFields(Map<String, String> values) {
		JSONObject obj = new JSONObject();
		if (values != null) for (Map.Entry<String, String> e : values.entrySet()) put(obj, e.getKey(), e.getValue() == null ? "" : e.getValue());
		return "customFields=" + enc(obj.toJSONString());
	}

	/** Body for {@code /assessments/image/{aid}}: the image as a data URI. */
	public static String image(byte[] bytes, String mimeType) {
		String dataUri = "data:" + mimeType + ";base64," + Base64.getEncoder().encodeToString(bytes);
		return "encodedImage=" + enc(dataUri);
	}

	public static String b64(String s) {
		return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}

	private static void appendB64(StringBuilder sb, String key, Object value) {
		if (value == null) return;
		sb.append('&').append(key).append('=').append(enc(b64(value.toString())));
	}

	private static String enc(String s) {
		return URLEncoder.encode(s, StandardCharsets.UTF_8);
	}

	private static String str(Object o) {
		return o == null ? "" : o.toString();
	}

	@SuppressWarnings("unchecked")
	private static void put(JSONObject o, String k, Object v) { o.put(k, v); }
}
