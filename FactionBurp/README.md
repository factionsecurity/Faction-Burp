# Faction Burp Extension

A Burp Suite extension (Montoya API) for sending findings to a Faction
instance. One build works with both generations of Faction; pick the one your
server runs in the extension's **Config** tab:

- **Faction 2.x** — [OWASP Faction](https://github.com/factionsecurity/OWASP-Faction-2),
  the current release. Uses the `/api/v1` REST API (bearer `sk_fac_…` key,
  JSON, fixed severity enum).
- **Faction 1.x** — the original [Faction](https://github.com/factionsecurity/faction).
  Uses the original API (`FACTION-API-KEY` header, form-encoded writes,
  server-defined risk levels).

If you are unsure which you have: OWASP Faction has an **API Keys** page under
Settings and issues keys starting with `sk_fac_`; the original Faction shows an
API token on the user profile.

## Features

- **Faction suite tab** with three sub-tabs:
  - **Queues** — active assessments and scheduled retests, polled on a timer.
  - **Assessment** — the selected assessment's scope and its findings;
    double-click a finding to view Description / Recommendation / Details, with a
    "Send to Repeater" link on embedded HTTP requests.
  - **Config** — Faction version, server URL, API key, refresh interval, a
    **Test Connection** button, and the Burp→Faction severity mapping.
- **Context-menu actions**:
  - Proxy / Target / Repeater: **Add as New Finding** and **Add to Existing Finding**.
  - Scanner audit issues: **Send Issues To Faction** (one finding per issue name).
- Assessment picker, severity selection, report **section** selection, and
  **custom fields** (text and dropdown).
- **Default-vulnerability** search to seed a new finding.
- Request/response evidence captured as HTML (optional cookie snipping and
  selection extraction), plus **image upload** (Insert Image button or paste an
  image directly).

## Build

Requires Java 17+ and Maven.

```
cd FactionBurp
mvn clean package
```

Load `target/FactionBurp-2.0-jar-with-dependencies.jar` in Burp
(Extensions → Add → Java).

### Releases

Publishing a GitHub release (tag `vX.Y` or `X.Y.Z`) runs the **Release**
workflow, which builds `FactionBurp-X.Y-jar-with-dependencies.jar` with the
version taken from the tag and attaches it to the release. The extension shows
that version in its Burp extension name and on the Config tab.

## Setup

1. In Burp, open the **Faction** tab → **Config**.
2. Choose the **Faction Version** that matches your server: **Faction 2.x** for
   OWASP Faction, **Faction 1.x** for the original Faction.
3. Enter the **Server** base URL, e.g. `https://faction.example.com` or
   `http://localhost:8080`. For 2.x the extension adds `/api/v1` itself; a
   pasted trailing `/api/v1` is stripped.
4. Enter the **API Key**:
   - **1.x**: the API token from your Faction user profile.
   - **2.x**: an API key created under Settings → API Keys with scope
     **READ_WRITE**, owned by a user with `vulnerabilities:create:*`,
     `assessments:edit:*` (inline images) and an `assessments:read:*` scope.
     Copy the `sk_fac_…` value — it is shown only once.
5. Set the **Refresh** interval (seconds) for queue polling.
6. Click **Save**, then **Test Connection**.
7. Map Burp severities (High/Medium/Low/Information) to Faction severities. On
   2.x the choices are CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL; on 1.x they are
   the risk levels your server defines (fetched after Save).

Config is stored in `~/.faction/faction.properties`. An existing 1.x
installation's server, token and severity mapping are picked up as-is; just
select "Faction 1.x" and Save.

## How the two versions differ inside the extension

The GUI is shared. `com.faction.api.FactionAPI` chooses a `FactionClient`
implementation from the configured version:

- `FactionV2Client` talks to `/api/v1` and unwraps the `{ data }` envelope.
- `FactionV1Client` talks to the original endpoints and translates their
  responses (PascalCase keys, epoch dates, numeric risk levels) into the 2.x
  shape through `V1Mapper`, so the rest of the extension has a single data model.

Known 1.x limitations:

- Assessment history (findings from an application's earlier assessments) is a
  2.x feature; on 1.x the findings table shows the selected assessment only.
- Boolean custom fields are not shown (the original extension skipped them too).
- Retests open their vulnerability by id only; 1.x does not report the
  assessment they belong to.
