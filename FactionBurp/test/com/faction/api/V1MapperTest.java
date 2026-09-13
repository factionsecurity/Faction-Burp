package com.faction.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.Test;

class V1MapperTest {

	private static JSONObject obj(String json) {
		try { return (JSONObject) new JSONParser().parse(json); } catch (Exception e) { throw new RuntimeException(e); }
	}

	private static JSONArray arr(String json) {
		try { return (JSONArray) new JSONParser().parse(json); } catch (Exception e) { throw new RuntimeException(e); }
	}

	// 2021-03-04T12:00:00Z — noon so the local-zone date is stable in tests
	private static final long EPOCH = 1614859200000L;

	@Test
	void isoDateHandlesEpochStringsNumbersNullAndGarbage() {
		assertEquals("2021-03-04", V1Mapper.isoDate("" + EPOCH));
		assertEquals("2021-03-04", V1Mapper.isoDate(EPOCH));
		assertEquals("", V1Mapper.isoDate(null));
		assertEquals("", V1Mapper.isoDate("not a date"));
		assertEquals("", V1Mapper.isoDate(""));
	}

	@Test
	void assessmentMapsKeysDatesSectionsAndScope() {
		JSONObject v1 = obj("{\"Id\":7,\"AppId\":\"APP-1\",\"Name\":\"Q3 test\",\"Start\":\"" + EPOCH + "\",\"End\":\"" + EPOCH
				+ "\",\"AccessNotes\":\"user/pass\",\"Notes\":\"<p>be careful</p>\"}");
		JSONArray sections = arr("[\"Default\",\"Web\"]");
		JSONObject a = V1Mapper.assessment(v1, sections);
		assertEquals("7", a.get("id"));
		assertEquals("APP-1", a.get("appId"));
		assertEquals("Q3 test", a.get("name"));
		assertEquals("2021-03-04", a.get("startDate"));
		assertEquals("2021-03-04", a.get("plannedEndDate"));
		assertEquals("Open", a.get("status"));
		assertEquals("", a.get("applicationName"));
		assertEquals("", a.get("applicationId"));
		assertEquals(sections, a.get("sections"));
		String scope = (String) a.get("scope");
		assertTrue(scope.contains("user/pass"), scope);
		assertTrue(scope.contains("<p>be careful</p>"), scope);
		assertTrue(scope.indexOf("user/pass") < scope.indexOf("be careful"), "access notes first: " + scope);
	}

	@Test
	void scopeHtmlOmitsEmptyParts() {
		assertEquals("", V1Mapper.scopeHtml(null, null));
		assertEquals("", V1Mapper.scopeHtml("", ""));
		String onlyNotes = V1Mapper.scopeHtml(null, "n");
		assertTrue(onlyNotes.contains("n") && !onlyNotes.contains("Access"), onlyNotes);
	}

	@Test
	void vulnerabilityMapsSummaryAndDetailFields() {
		JSONObject v1 = obj("{\"Id\":42,\"Name\":\"XSS\",\"OverallStr\":\"High\",\"ImpactStr\":\"Medium\",\"LikelyhoodStr\":\"High\","
				+ "\"Opened\":\"" + EPOCH + "\",\"Closed\":null,\"Description\":\"d\",\"Recommendation\":\"r\",\"Details\":\"x\","
				+ "\"Section\":\"Web\",\"CustomFields\":[{\"Key\":\"Affected URL\",\"Value\":\"/a\"},{\"Key\":\"Empty\",\"Value\":null}]}");
		JSONObject v = V1Mapper.vulnerability(v1);
		assertEquals("42", v.get("id"));
		assertEquals("XSS", v.get("name"));
		assertEquals("High", v.get("severity"));
		assertEquals("Medium", v.get("impact"));
		assertEquals("High", v.get("likelihood"));
		assertEquals("2021-03-04", v.get("openedAt"));
		assertNull(v.get("closedAt"));
		assertEquals("d", v.get("description"));
		assertEquals("r", v.get("recommendation"));
		assertEquals("x", v.get("details"));
		assertEquals("Web", v.get("section"));
		JSONObject fv = (JSONObject) v.get("fieldValues");
		assertEquals("/a", fv.get("Affected URL"));
		assertEquals("", fv.get("Empty"));
	}

	@Test
	void vulnerabilityWithoutOpenedDateHasNoOpenedAt() {
		JSONObject v = V1Mapper.vulnerability(obj("{\"Id\":1,\"Name\":\"n\"}"));
		assertNull(v.get("openedAt"));
		assertNull(v.get("closedAt"));
	}

	@Test
	void retestMapsQueueRow() {
		JSONObject r = V1Mapper.retest(obj("{\"Id\":9,\"Start\":\"" + EPOCH + "\",\"AssessmentName\":\"A\",\"Name\":\"SQLi\",\"OverallStr\":\"Critical\"}"));
		assertEquals("2021-03-04", r.get("scheduledStartDate"));
		assertEquals("A", r.get("assessmentName"));
		assertEquals("SQLi", r.get("vulnerabilityName"));
		assertEquals("Critical", r.get("vulnerabilitySeverity"));
		assertEquals("9", r.get("vulnerabilityId"));
		assertEquals("REQUESTED", r.get("status"));
		assertEquals("", r.get("assessmentId"));
	}

	@Test
	void defaultVulnResolvesSeverityIdToLevelName() {
		Map<Integer, String> levels = Map.of(4, "critical", 3, "high", 0, "informational");
		JSONObject dv = V1Mapper.defaultVuln(obj("{\"Id\":5,\"Name\":\"CSRF\",\"Overall\":3,\"Description\":\"d\",\"Recommendation\":\"r\"}"), levels);
		assertEquals("5", dv.get("id"));
		assertEquals("5", dv.get("defaultVulnerabilityId"));
		assertEquals("CSRF", dv.get("name"));
		assertEquals("high", dv.get("severity"));
		assertEquals("d", dv.get("description"));
		assertEquals("r", dv.get("recommendation"));
		// Unknown level id -> no severity so the GUI keeps its current selection
		assertNull(V1Mapper.defaultVuln(obj("{\"Id\":6,\"Name\":\"x\",\"Overall\":99}"), levels).get("severity"));
	}

	@Test
	void stringCustomFieldMapsToSTRING() {
		JSONObject f = V1Mapper.customField(obj("{\"Key\":\"Affected URL\",\"FieldType\":\"String\",\"DefaultValue\":\"http://\",\"Readonly\":false}"));
		assertEquals("Affected URL", f.get("variableName"));
		assertEquals("Affected URL", f.get("displayName"));
		assertEquals("STRING", f.get("fieldType"));
		assertEquals("http://", f.get("defaultValue"));
		assertEquals(Boolean.FALSE, f.get("readOnly"));
	}

	@Test
	void listFieldBecomesDropdownWithOptionsSplitFromDefaultValue() {
		JSONObject f = V1Mapper.customField(obj("{\"Key\":\"Env\",\"FieldType\":\"List\",\"DefaultValue\":\"a, b,,c\"}"));
		assertEquals("DROPDOWN", f.get("fieldType"));
		assertEquals(List.of("a", "b", "c"), f.get("dropdownOptions"));
		assertEquals("", f.get("defaultValue"));
	}

	@Test
	void booleanFieldIsDroppedAndRichTextIsMarked() {
		assertNull(V1Mapper.customField(obj("{\"Key\":\"Flag\",\"FieldType\":\"Boolean\"}")));
		assertEquals("RICH_TEXT", V1Mapper.customField(obj("{\"Key\":\"Body\",\"FieldType\":\"Rich Text\"}")).get("fieldType"));
		assertEquals("STRING", V1Mapper.customField(obj("{\"Key\":\"NoType\"}")).get("fieldType"));
	}

	@Test
	void customFieldsSkipsDroppedEntriesAndNulls() {
		JSONArray out = V1Mapper.customFields(arr("[{\"Key\":\"A\",\"FieldType\":\"String\"},{\"Key\":\"B\",\"FieldType\":\"Boolean\"},{\"FieldType\":\"String\"}]"));
		assertEquals(1, out.size());
		assertEquals("A", ((JSONObject) out.get(0)).get("variableName"));
		assertEquals(0, V1Mapper.customFields(null).size());
	}

	@Test
	void markdownImageUrlFindsTheLinkTargetInAnyKey() {
		assertEquals("/img/1", V1Mapper.markdownImageUrl(obj("{\"Markdown\":\"![evidence](/img/1)\"}")));
		assertEquals("http://h/x.png", V1Mapper.markdownImageUrl(obj("{\"id\":3,\"link\":\"![a](http://h/x.png)\"}")));
		assertEquals("/direct.png", V1Mapper.markdownImageUrl(obj("{\"url\":\"/direct.png\"}")));
		assertNull(V1Mapper.markdownImageUrl(obj("{\"id\":3}")));
		assertNull(V1Mapper.markdownImageUrl(null));
	}
}
