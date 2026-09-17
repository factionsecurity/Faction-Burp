# Merge Faction 1.x / 2.x Extensions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One Burp extension, built from FactionBurp2's code, that talks to a Faction 1.x or 2.x server depending on a Config-tab version switch.

**Architecture:** The GUI keeps holding a `FactionAPI`, which becomes a facade owning `FactionConfig` and delegating every call to a `FactionClient` implementation chosen by `apiVersion`. `FactionV2Client` is today's transport; `FactionV1Client` speaks the old form-encoded protocol and normalises its JSON into the v2 shape through pure `V1Mapper` functions.

**Tech Stack:** Java 17, Maven, Burp Montoya API 2023.12.1 (provided), json-simple 1.1.1, commonmark 0.7.1, commons-lang3, JUnit 5.

**Spec:** `docs/superpowers/specs/2026-09-13-merge-v1-v2-extensions-design.md`

## Global Constraints

- Java release 17; Maven `mvn clean package` must pass with all tests.
- Module directory is `FactionBurp/`; artifact `FactionBurp`, version `2.0`.
- Config file `~/.faction/faction.properties`; keys `apiVersion`, `server`, `token`, `refresh`, `high`, `medium`, `low`, `information`.
- All `FactionClient` methods return v2-shaped JSON; the GUI never sees v1 key names.
- Single final commit on branch `adding-custom-fields`. Do not commit between tasks; run `mvn -q test` instead as each task's gate.

---

### Task 1: Replace FactionBurp's contents with FactionBurp2's code

**Files:**
- Delete: `FactionBurp/src/**`, `FactionBurp/.classpath`, `FactionBurp/.project`, `FactionBurp/.settings/`, `FactionBurp/target/`, `FactionBurp/.github/`
- Replace: `FactionBurp/pom.xml`, `FactionBurp/mise.toml`, `FactionBurp/.gitignore`, `FactionBurp/README.md` (from FactionBurp2)
- Copy: `FactionBurp2/src/**` → `FactionBurp/src/**`, `FactionBurp2/test/**` → `FactionBurp/test/**`
- Delete: `FactionBurp2/` (untracked)

- [ ] Step 1: `rm -rf FactionBurp/src FactionBurp/.classpath FactionBurp/.project FactionBurp/.settings FactionBurp/target FactionBurp/.github`
- [ ] Step 2: `cp -R FactionBurp2/src FactionBurp/src && cp -R FactionBurp2/test FactionBurp/test && cp FactionBurp2/pom.xml FactionBurp2/mise.toml FactionBurp2/.gitignore FactionBurp2/README.md FactionBurp/`
- [ ] Step 3: In `FactionBurp/pom.xml` set groupId/artifactId to `FactionBurp` and `<finalName>FactionBurp-${project.version}</finalName>`.
- [ ] Step 4: `rm -rf FactionBurp2`
- [ ] Step 5: `cd FactionBurp && mvn -q test` → 6 test classes pass.

### Task 2: `FactionConfig`

**Files:**
- Create: `FactionBurp/src/com/faction/api/FactionConfig.java`
- Test: `FactionBurp/test/com/faction/api/FactionConfigTest.java`

**Interfaces (produces):**
```java
public final class FactionConfig {
  public static final String BURP_SEV_HIGH="high", BURP_SEV_MED="medium", BURP_SEV_LOW="low", BURP_SEV_INFO="information";
  public FactionConfig(Path file);               // test constructor
  public static FactionConfig defaultLocation(); // ~/.faction/faction.properties
  public void reload();
  public int getApiVersion();                    // 1 or 2, default 2
  public String getServer(); public String getToken(); public int getRefresh();
  public String getSeverity(String burpKey);     // raw stored value, "" if unset
  public void save(int apiVersion, String server, String token, String refresh);
  public void saveSeverity(String burpKey, String factionSeverity);
  public static String normaliseServer(String s);
}
```
Behaviour: `save` normalises the server (trim, strip trailing `/`, strip trailing `/api/v1`), parses refresh with fallback 20, clamps apiVersion to {1,2}. Missing file/dir is created. `getSeverity` returns whatever is stored (numeric legacy values included) so the v1 client can resolve them.

- [ ] Step 1: Write `FactionConfigTest` with tests: `defaultsToVersion2WhenFileEmpty`, `roundTripsSavedValues` (version 1, server `http://h:8080/api/v1/` → `http://h:8080`, token, refresh "30"), `badRefreshFallsBackTo20`, `severityIsStoredAsGiven` (saves "HIGH", then reads back), `legacyNumericSeverityIsPreserved` (pre-write `high=4` to the file, reload, `getSeverity("high")` is `"4"`).
- [ ] Step 2: Run → compile failure.
- [ ] Step 3: Implement `FactionConfig` (move persistence code out of the v2 `FactionAPI`).
- [ ] Step 4: `mvn -q test` passes.

### Task 3: `FactionClient` interface and `FactionV2Client`

**Files:**
- Create: `FactionBurp/src/com/faction/api/FactionClient.java`
- Create: `FactionBurp/src/com/faction/api/FactionV2Client.java` (from current `FactionAPI.java`)
- Create: `FactionBurp/src/com/faction/api/Transport.java` (shared Montoya send + logging helpers)

**Interfaces (produces):**
```java
public interface FactionClient {
  boolean isConfigured();
  String testConnection();                       // null when OK
  String[] getSeverityStrings();
  String getSevMapping(String burpSeverity);
  JSONArray getAssessments();
  JSONObject getAssessment(String assessmentId);
  JSONArray getAssessmentsForApplication(String applicationId);
  JSONArray getVulnerabilities(String assessmentId);
  JSONObject getVulnerability(String assessmentId, String vulnId);
  JSONArray getRetests();
  JSONArray searchDefaultVulns(String query);
  JSONArray getVulnerabilityFields(String assessmentId);
  JSONObject createVulnerabilityWithFields(String assessmentId, JSONObject body, Map<String,String> fieldValuesByVariableName);
  JSONObject appendDetails(String assessmentId, String vulnId, String html, String severity);
  JSONObject setSection(String assessmentId, String vulnId, String section);
  JSONObject setCustomFieldValues(String assessmentId, String vulnId, Map<String,String> valuesByVariableName);
  String uploadInlineImage(String assessmentId, byte[] bytes, String filename, String mimeType);
  byte[] getBytes(String path);
  void clearCaches();
}
```
`Transport` wraps `MontoyaApi.http()` + `logging`: `HttpService service(String server)`, `String hostHeader(String server)`, `String basePath(String server)`, `HttpRequestResponse send(HttpRequest, String method, String path, String serverForLog)`, `logFailure(...)`. Both clients use it.

- [ ] Step 1: Create `FactionClient`. Move the v2 code into `FactionV2Client implements FactionClient` taking `(Transport t, FactionConfig cfg)`; it reads server/token from `cfg`. Add `getVulnerabilityFields(String)` (ignores arg), `appendDetails(...,severity)` (ignores severity), `setCustomFieldValues` (moved from `SendToFaction.patchExistingCustomFields`), strip `defaultVulnerabilityId` from create bodies.
- [ ] Step 2: Compile only (`mvn -q compile`); GUI still references old `FactionAPI` — that is Task 6. Keep the old `FactionAPI.java` for now so compilation succeeds.

### Task 4: `V1Mapper`

**Files:**
- Create: `FactionBurp/src/com/faction/api/V1Mapper.java`
- Test: `FactionBurp/test/com/faction/api/V1MapperTest.java`

**Interfaces (produces):**
```java
public final class V1Mapper {
  public static String isoDate(Object epochMillis);              // "" on null/garbage
  public static JSONObject assessment(JSONObject v1, JSONArray sections);
  public static JSONObject vulnerability(JSONObject v1);
  public static JSONObject retest(JSONObject v1);
  public static JSONObject defaultVuln(JSONObject v1, Map<Integer,String> levelNamesById);
  public static JSONObject customField(JSONObject v1);           // null when dropped (Boolean)
  public static JSONArray customFields(JSONArray v1);
  public static String scopeHtml(Object accessNotes, Object notes);
  public static String markdownImageUrl(JSONObject imageResponse); // null if none
}
```

- [ ] Step 1: Write tests, one per mapping row in the spec's `V1Mapper` table, plus `isoDateHandlesNullAndGarbage`, `dropdownOptionsSplitFromDefaultValue` (`DefaultValue="a, b,,c"` → `["a","b","c"]`, `defaultValue=""`), `booleanFieldIsDropped`, `richTextMapsToRICH_TEXT`, `markdownImageUrlFindsLinkInAnyKey` (`{"Markdown":"![x](/img/1)"}` → `/img/1`), `vulnerabilityMapsCustomFieldsToFieldValues`.
- [ ] Step 2: Run → fail. Step 3: implement. Step 4: pass.

### Task 5: `FactionV1Client`

**Files:**
- Create: `FactionBurp/src/com/faction/api/FactionV1Client.java`
- Create: `FactionBurp/src/com/faction/api/V1Forms.java` (pure form-body builders)
- Test: `FactionBurp/test/com/faction/api/V1FormsTest.java`

**Interfaces (produces):**
```java
public final class V1Forms {
  public static String createVuln(JSONObject body, Integer severityId, Map<String,String> customFields, String section);
  //  name=<enc>&feed=false&details=<enc b64>&description=<enc b64>&recommendation=<enc b64>&severity=<id>[&customFields=<enc json>][&section=<enc>]
  public static String appendDetails(String html, Integer severityId); // feed=false&details=<enc b64>[&severity=<id>]
  public static String section(String section);                      // section=<enc>
  public static String customFields(Map<String,String> values);       // customFields=<enc json>
  public static String image(byte[] bytes, String mime);             // encodedImage=<enc data-uri>
  public static String b64(String s);
}
```
`FactionV1Client implements FactionClient` with `(Transport, FactionConfig)`. Endpoint constants copied from the old client. Header `FACTION-API-KEY`, `Content-Type: application/x-www-form-urlencoded`, `Accept: application/json`, `Content-Language: en-US`; GET paths replace `+` with `%20`. Caches: `levelMap` (name→id, from `/vulnerabilities/getrisklevels/`), `sections` (`/assessments/report-sections`), `customFields` per aid, `queue` (last `/assessments/queue` result, refreshed by `getAssessments`). `getSevMapping` resolves a numeric stored value through `levelMap`. `testConnection` returns null when `/getrisklevels` yields a non-empty JSON array; `"Authentication failed"` on 401/403; HTML hint otherwise.

- [ ] Step 1: `V1FormsTest`: exact expected strings for each builder (use a fixed input, compute expected with `URLEncoder`/`Base64` in the test).
- [ ] Step 2: fail → implement `V1Forms` → pass.
- [ ] Step 3: Implement `FactionV1Client` per the spec table. `mvn -q compile`.

### Task 6: `FactionAPI` facade + GUI wiring

**Files:**
- Rewrite: `FactionBurp/src/com/faction/api/FactionAPI.java`
- Modify: `FactionBurp/src/com/faction/gui/SendToFaction.java`, `FactionGUI.java`, `FSUtils.java`, `burp/BurpExtender.java`
- Test: `FactionBurp/test/com/faction/api/FactionAPITest.java`

**Interfaces (produces):**
```java
public class FactionAPI implements FactionClient {
  public FactionAPI(MontoyaApi api);                      // production
  FactionAPI(FactionConfig cfg, Function<Integer,FactionClient> factory); // test
  public FactionConfig config();
  public int getApiVersion(); public String getServer(); public String getToken(); public int getRefresh();
  public void updateProps(int apiVersion, String server, String token, String refresh); // saves + rebuilds client
  public void updateSev(String burpKey, String factionSeverity);
  // every FactionClient method delegates to the active client
}
```
- [ ] Step 1: `FactionAPITest`: `selectsV2ByDefault`, `selectsV1WhenConfigured`, `updatePropsSwapsClient` (fake factory returns stub clients tagged by version; assert `getSeverityStrings()` comes from the expected stub).
- [ ] Step 2: fail → implement facade → pass.
- [ ] Step 3: GUI edits:
  - `SendToFaction.loadCustomFields()` → `factionApi.getVulnerabilityFields(aid)`; `saveNewFinding` puts `defaultVulnerabilityId` from the chosen default vuln; `saveToExisting` → `appendDetails(aid, vid, details, ""+severity.getSelectedItem())` and `setCustomFieldValues(aid, vid, cf)`; delete `patchExistingCustomFields`.
  - `FactionGUI.buildConfigTab()`: add `JComboBox<String> versionBox` with `"Faction 1.x"`, `"Faction 2.x"` at y=54, shift the other rows down 39px; Save/Test call `updateProps(selectedVersion, …)`; after Save call `rebuildSeverityRows()` which removes the four combos/labels and re-adds them. `openVulnerability` guard: only `vulnId` must be non-empty.
  - `BurpExtender`: `setName("Faction")`.
  - `FSUtils.setSeverityComboBoxDefaults` signature unchanged (takes `FactionAPI`).
- [ ] Step 4: `mvn -q test` green; `mvn -q package` produces `target/FactionBurp-2.0-jar-with-dependencies.jar`.

### Task 7: Docs

**Files:**
- Modify: `README.md` (root), `FactionBurp/README.md`

- [ ] Step 1: Root README: build path `FactionBurp`, jar name, "Config → Faction Version" note.
- [ ] Step 2: `FactionBurp/README.md`: rewrite the v2 README as the single extension's README with a "Choosing the Faction version" section (1.x: API token from the old UI + `FACTION-API-KEY`; 2.x: `sk_fac_` key), config file name, and the 1.x gaps (no history, Boolean fields skipped).

### Task 8: Verify and commit

- [ ] Step 1: `cd FactionBurp && mvn clean package` → BUILD SUCCESS, tests listed.
- [ ] Step 2: `git status` shows `FactionBurp/**` changes, docs, no `FactionBurp2/`.
- [ ] Step 3: Single commit: `git add -A FactionBurp docs README.md .vscode && git commit` with a message describing the merge and the version switch.
