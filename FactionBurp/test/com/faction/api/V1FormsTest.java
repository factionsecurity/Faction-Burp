package com.faction.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.json.simple.JSONObject;
import org.junit.jupiter.api.Test;

class V1FormsTest {

	private static String enc(String s) {
		return URLEncoder.encode(s, StandardCharsets.UTF_8);
	}

	private static String b64(String s) {
		return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
	}

	@SuppressWarnings("unchecked")
	private static JSONObject body(String name, String details, String description, String recommendation) {
		JSONObject b = new JSONObject();
		b.put("name", name);
		if (details != null) b.put("details", details);
		if (description != null) b.put("description", description);
		if (recommendation != null) b.put("recommendation", recommendation);
		return b;
	}

	@Test
	void createVulnEncodesEverythingTheOldExtensionSent() {
		Map<String, String> cf = new LinkedHashMap<>();
		cf.put("Affected URL", "/a?b=1");
		String form = V1Forms.createVuln(body("XSS & more", "<pre>x</pre>", "desc", "rec"), 3, cf, "Web App");
		String expected = "name=" + enc("XSS & more")
				+ "&feed=false"
				+ "&details=" + enc(b64("<pre>x</pre>"))
				+ "&description=" + enc(b64("desc"))
				+ "&recommendation=" + enc(b64("rec"))
				+ "&severity=3"
				+ "&customFields=" + enc("{\"Affected URL\":\"\\/a?b=1\"}")
				+ "&section=" + enc("Web App");
		assertEquals(expected, form);
	}

	@Test
	void createVulnOmitsAbsentParts() {
		String form = V1Forms.createVuln(body("n", "d", null, null), null, null, "");
		assertEquals("name=n&feed=false&details=" + enc(b64("d")), form);
	}

	@Test
	void appendDetailsCarriesSeverityWhenKnown() {
		assertEquals("feed=false&details=" + enc(b64("<p>x</p>")) + "&severity=2", V1Forms.appendDetails("<p>x</p>", 2));
		assertEquals("feed=false&details=" + enc(b64("y")), V1Forms.appendDetails("y", null));
	}

	@Test
	void sectionAndCustomFieldsAreSingleParameters() {
		assertEquals("section=" + enc("Web App"), V1Forms.section("Web App"));
		Map<String, String> cf = new LinkedHashMap<>();
		cf.put("K", "v");
		assertEquals("customFields=" + enc("{\"K\":\"v\"}"), V1Forms.customFields(cf));
	}

	@Test
	void imageIsSentAsAnEncodedDataUri() {
		byte[] bytes = { 1, 2, 3 };
		String dataUri = "data:image/png;base64," + Base64.getEncoder().encodeToString(bytes);
		assertEquals("encodedImage=" + enc(dataUri), V1Forms.image(bytes, "image/png"));
	}
}
