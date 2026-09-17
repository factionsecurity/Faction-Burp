# Merge the Faction 1.x and 2.x Burp extensions into one

Date: 2026-09-13
Branch: adding-custom-fields

## Goal

Ship a single Burp extension that talks to either a Faction 1.x server (the
original form-encoded API) or a Faction 2.x server (the `/api/v1` REST API),
selected in the extension's Config tab. The user-facing behaviour is that of the
FactionBurp2 extension, which is the more recent and more thoroughly fixed of
the two; the 1.x support is a protocol adapter behind it.

## Non-goals

- Preserving the 1.x GUI code. It is superseded.
- Auto-detecting the server version. The user picks it.
- Supporting Java 8. The merged code requires Java 17 (records are used).
- Boolean and rich-text custom fields on 1.x. The original extension skipped
  them; the merged one does too.

## Layout

`FactionBurp/` becomes the merged Maven module and keeps its git history. Its
contents are replaced by FactionBurp2's sources, tests and pom (artifact
`FactionBurp`, version `2.0`, Java 17, `mvn clean package` produces
`target/FactionBurp-2.0-jar-with-dependencies.jar`). `FactionBurp2/` is deleted;
it was never tracked. Eclipse metadata (`.classpath`, `.project`, `.settings/`)
and the legacy `burp-extender-api` dependency go away with the v1 code.

## Architecture

```
GUI (FactionGUI, SendToFaction, VulnerabilityDetailsPane, Base64ImageView, FSUtils)
        │  holds a FactionAPI
        ▼
FactionAPI  (facade: owns FactionConfig, picks and delegates to the active client)
        │  implements FactionClient
        ├── FactionV2Client  (today's v2 transport, /api/v1 + bearer + envelope)
        └── FactionV1Client  (v1 transport + V1Mapper normalisers)
```

### `FactionConfig`

Owns `~/.faction/faction.properties`. Keys: `apiVersion` (`1` or `2`, default
`2`), `server`, `token`, `refresh`, and the Burp→Faction severity mapping under
`high`, `medium`, `low`, `information`. Severity values are stored as Faction
severity *names* for both versions. A numeric value (what the 1.x extension used
to write) is kept as-is in the file and resolved to a name by the v1 client via
the risk-level map, so existing 1.x users keep their mapping.

Server URL normalisation (trailing slash, trailing `/api/v1`) is applied on
save for both versions.

### `FactionClient` interface

All methods return v2-shaped JSON (`org.json.simple`), so the GUI has one data
model. Methods:

| Method | v2 | v1 |
|---|---|---|
| `isConfigured()` | server + token present | same |
| `testConnection()` → error or null | `GET /auth/me` | `GET /vulnerabilities/getrisklevels/` must return a JSON array |
| `getSeverityStrings()` | fixed enum | level names from `/getrisklevels`, cached |
| `getSevMapping(burpSev)` → name | from config | from config; numeric legacy values resolved via level map |
| `getAssessments()` | `/assessments?showCompleted=false…`, drop `completedDate != null` | `/assessments/queue`, mapped; each gets `sections` from `/assessments/report-sections` (cached) and `scope` built from `AccessNotes` + `Notes` |
| `getAssessment(aid)` | `/assessments/{aid}` | found in the queue result by `Id` |
| `getAssessmentsForApplication(appId)` | `/assessments?applicationId=…` | empty array (no 1.x equivalent) |
| `getVulnerabilities(aid)` | `/assessments/{aid}/vulnerabilities` | `/assessments/vulns/{aid}`, mapped |
| `getVulnerability(aid, vid)` | `/assessments/{aid}/vulnerabilities/{vid}` | `/assessments/vuln/{vid}`, mapped |
| `getRetests()` | `/retests?status=…` | `/verifications/queue`, mapped |
| `searchDefaultVulns(q)` | client-side filter of `/default-vulnerabilities` | `/vulnerabilities/default/{q}`, mapped |
| `getVulnerabilityFields(aid)` | `/report-templates/vulnerability-fields`, cached (ignores aid) | `/assessments/customfields/{aid}` → `vulnerabilityFields`, mapped, cached per aid |
| `createVulnerabilityWithFields(aid, body, fieldValues)` | POST JSON, then PATCH `fieldValues` resolved via `fieldDefinitions` | form POST to `/assessments/addVuln/{aid}`, or `/assessments/addDefaultVuln/{aid}/{dvId}` when `body.defaultVulnerabilityId` is set; `customFields` and `section` inline |
| `appendDetails(aid, vid, html, severity)` | GET then PATCH `details` | form POST to `/assessments/addVuln/{aid}/{vid}` with `details` + `severity` |
| `setSection(aid, vid, section)` | PATCH `section` | form POST `section=` to `/assessments/vuln/{vid}` |
| `setCustomFieldValues(aid, vid, map)` | GET, resolve `fieldDefinitions`, PATCH `fieldValues` | form POST `customFields=` to `/assessments/vuln/{vid}/customfields` |
| `uploadInlineImage(aid, bytes, name, mime)` → url | multipart to `/assessments/{aid}/inline-images` | form POST `encodedImage=<data URI>` to `/assessments/image/{aid}`; URL extracted from the returned markdown link |
| `getBytes(path)` | GET with bearer | GET with `FACTION-API-KEY` |
| `clearCaches()` | drop field cache | drop level, section and field caches |

The `body` passed to `createVulnerabilityWithFields` is the v2
`CreateVulnerabilityRequest` shape (`name`, `severity`, `details`,
`description`, `recommendation`, `section`, optional `defaultVulnerabilityId`).
The v2 client strips `defaultVulnerabilityId`; the v1 client base64-encodes
`details`, `description` and `recommendation`, translates the severity name to
a level id, and form-encodes.

### `V1Mapper` (pure functions, unit-tested)

| v1 → v2 | Notes |
|---|---|
| assessment: `Id`→`id`, `AppId`→`appId`, `Name`→`name`, `Start`→`startDate`, `End`→`plannedEndDate`, `AccessNotes`+`Notes`→`scope` (HTML, separated by a heading), `sections` attached, `status` = `"Open"` | dates: epoch ms → `yyyy-MM-dd` |
| vulnerability (list/detail): `Id`→`id`, `Name`→`name`, `OverallStr`→`severity`, `Opened`→`openedAt`, `Closed`→`closedAt`, `Description`/`Recommendation`/`Details`/`Section` → lower-case, `CustomFields[{Key,Value}]` → `fieldValues` (map) | |
| retest: `Start`→`scheduledStartDate`, `AssessmentName`→`assessmentName`, `Name`→`vulnerabilityName`, `OverallStr`→`vulnerabilitySeverity`, `Id`→`vulnerabilityId`, `status`=`"REQUESTED"`, `assessmentId`=`""` | |
| default vuln: `Id`→`id`, `Name`→`name`, `Overall` (level id) → `severity` (level name), `Description`/`Recommendation` if present, `defaultVulnerabilityId`=`Id` | |
| custom field: `Key`→`variableName` and `displayName`, `DefaultValue`→`defaultValue`, `FieldType`: `List`→`DROPDOWN` with `dropdownOptions` split on `,` from `DefaultValue` (and `defaultValue` cleared), `Rich Text`→`RICH_TEXT`, `Boolean`→ dropped, else `STRING`; `Readonly`→`readOnly` | |

### GUI changes (small, in FactionBurp2's code)

- `SendToFaction`: call `getVulnerabilityFields(aid)`; put the selected default
  vuln's `id` in the body as `defaultVulnerabilityId`; call
  `appendDetails(aid, vid, html, severity)`; replace the inline
  `patchExistingCustomFields` with `factionApi.setCustomFieldValues`; prefill
  the section/custom fields from `fieldValues` when they exist (existing-finding
  mode).
- `FactionGUI` config tab: a "Faction Version" combo (`1.x` / `2.x`) above the
  server field; Save persists it, rebuilds the client, and re-populates the four
  severity combos (their option lists differ per version). `openVulnerability`
  requires only a vulnerability id, since 1.x retests carry no assessment id.
- `BurpExtender`: extension name "Faction".

### Error handling

Unchanged from v2: transport failures are logged to Burp's extension Errors tab
with URL, status, body and the request; list calls return empty arrays and
object calls return null. The v1 client reuses the same logger. Unparseable
1.x fields (e.g. non-numeric dates) map to `""` rather than throwing.

### Testing

- Existing v2 JUnit tests move with the code and keep passing.
- New tests: `V1MapperTest` (every mapping above, including legacy numeric
  severity resolution and the dropdown split), `V1FormEncodingTest` (the exact
  form bodies for create / addDefault / append / section / customfields / image),
  `FactionConfigTest` (version default, round-trip, URL normalisation, numeric
  legacy severity kept), and `FactionAPITest` (facade selects the client that
  matches `apiVersion` and swaps it on save). Transport code is kept thin and
  is not unit-tested; it needs Burp.
- Manual: build the jar, load it in Burp, confirm the Config tab shows the
  version switch and Test Connection works against the available 2.x server.

## Out of scope / known gaps

- No 1.x server is available for end-to-end testing; the v1 client is built
  from the exact endpoints, field names and encodings of the original code.
- Assessment history (findings from an application's other assessments) is a
  2.x feature; on 1.x the findings table shows the selected assessment only.
