package com.faction.api;

import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

/**
 * What the extension needs from a Faction server, independent of which API
 * generation the server speaks. Every method returns JSON in the 2.x shape
 * (lower-camel keys: {@code id}, {@code name}, {@code appId}, {@code severity},
 * ISO dates, …); the 1.x implementation translates on the way in and out so the
 * GUI has a single data model.
 *
 * List methods never return null (empty array on failure); object methods
 * return null on failure. Failures are logged to Burp's extension Errors tab.
 */
public interface FactionClient {

	/** True when a server URL and API key are present. */
	boolean isConfigured();

	/** Null when the saved credentials authenticate, else a human-readable error. */
	String testConnection();

	/** All Faction severity names, for populating dropdowns. */
	String[] getSeverityStrings();

	/** Maps a Burp severity ("high"/"medium"/"low"/"information") to a Faction severity name. */
	String getSevMapping(String burpSeverity);

	/** Open assessments. Fields: id, appId, name, applicationName, status, startDate, plannedEndDate, sections. */
	JSONArray getAssessments();

	/** One assessment; adds {@code scope} (HTML) and {@code applicationId}. */
	JSONObject getAssessment(String assessmentId);

	/** Every assessment of an application, completed ones included (empty on 1.x). */
	JSONArray getAssessmentsForApplication(String applicationId);

	/** Findings of an assessment: id, name, severity, openedAt, closedAt. */
	JSONArray getVulnerabilities(String assessmentId);

	/** One finding: name, description, recommendation, details, section, fieldDefinitions / fieldValues. */
	JSONObject getVulnerability(String assessmentId, String vulnId);

	/** Open retests: scheduledStartDate, assessmentName, vulnerabilityName, vulnerabilitySeverity, status, vulnerabilityId, assessmentId. */
	JSONArray getRetests();

	/** Default-vulnerability templates whose name contains the query: id, name, severity, description, recommendation, defaultVulnerabilityId. */
	JSONArray searchDefaultVulns(String query);

	/** Vulnerability custom-field definitions: variableName, displayName, fieldType (STRING/DROPDOWN/RICH_TEXT), defaultValue, dropdownOptions. */
	JSONArray getVulnerabilityFields(String assessmentId);

	/**
	 * Creates a finding. {@code body} is the 2.x CreateVulnerabilityRequest shape
	 * (name, severity, details, description, recommendation, section) plus an
	 * optional {@code defaultVulnerabilityId}; {@code fieldValuesByVariableName}
	 * carries custom-field values. Returns the created finding or null.
	 */
	JSONObject createVulnerabilityWithFields(String assessmentId, JSONObject body, Map<String, String> fieldValuesByVariableName);

	/** Appends HTML to an existing finding's details. {@code severity} is used by 1.x only. */
	JSONObject appendDetails(String assessmentId, String vulnId, String html, String severity);

	/** Sets the report section of an existing finding. */
	JSONObject setSection(String assessmentId, String vulnId, String section);

	/** Sets custom-field values on an existing finding. */
	JSONObject setCustomFieldValues(String assessmentId, String vulnId, Map<String, String> valuesByVariableName);

	/** Uploads an image for embedding in a finding; returns the image URL/path or null. */
	String uploadInlineImage(String assessmentId, byte[] imageBytes, String filename, String mimeType);

	/** Fetches a server-hosted binary (an inline image) with the API credentials; null on failure. */
	byte[] getBytes(String path);

	/** Drops session caches so the next access re-fetches. */
	void clearCaches();
}
