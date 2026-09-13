package com.faction.gui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

import javax.imageio.ImageIO;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.TransferHandler;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.apache.commons.lang3.StringEscapeUtils;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.nio.charset.StandardCharsets;
import com.faction.utils.CodeBlockHtml;
import com.faction.utils.HtmlPretty;
import com.faction.api.FactionAPI;
import com.faction.utils.FSUtils;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext;

/**
 * The "Send to Faction" window. Supports three flows (against a 1.x or 2.x server):
 *   - Add a new finding from a request/response.
 *   - Append a request/response to an existing finding.
 *   - Import selected Scanner audit issues as findings.
 */
public class SendToFaction {

	public JFrame frame;
	private final FactionAPI factionApi;
	private final Object event;
	private final boolean isNew;
	private final boolean isScanIssue;
	private final String preselectAssessmentId;

	private JTextField vulnName;
	private JComboBox<String> assessmentList;
	private JComboBox<String> vulnList;
	private JComboBox<String> severity;
	private JComboBox<String> sections;
	private JComboBox<String> defaultVulns;
	private JTextField vulnSearch;
	private JCheckBox optReq;
	private JCheckBox optCookies;
	private JCheckBox optResp;
	private JCheckBox useSelected;
	private JEditorPane message_1;
	private JButton btnSave;
	private JProgressBar imageSpinner;
	private JPanel customFieldsPanel;

	private JSONArray asmts;
	private JSONArray vulns;
	private final Map<String, JSONObject> defaultVulnsByName = new HashMap<>();
	// Custom field widgets and their definitions, keyed by variableName.
	private final LinkedHashMap<String, Component> customFieldComponents = new LinkedHashMap<>();
	private final LinkedHashMap<String, JSONObject> customFieldDefs = new LinkedHashMap<>();

	private HashMap<String, List<AuditIssue>> scanIssues;

	public SendToFaction(Object event, boolean isScan, boolean isNew, String appId, FactionAPI factionApi) {
		this.event = event;
		this.isScanIssue = isScan;
		this.isNew = isNew;
		this.preselectAssessmentId = appId;
		this.factionApi = factionApi;

		if (isScanIssue) {
			List<AuditIssue> selectedIssues = ((AuditIssueContextMenuEvent) event).selectedIssues();
			scanIssues = new HashMap<>();
			for (AuditIssue issue : selectedIssues) {
				scanIssues.computeIfAbsent(issue.name(), k -> new ArrayList<>()).add(issue);
			}
		}
		initialize();
	}

	private void initialize() {
		frame = new JFrame(isNew ? "Add Finding to Faction" : "Add to Existing Finding");
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		frame.setBounds(100, 100, 1080, 780);
		GridBagLayout gbl = new GridBagLayout();
		gbl.columnWidths = new int[] { 0, 140, 0, 260, 0 };
		gbl.rowHeights = new int[] { 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
		gbl.columnWeights = new double[] { 0.0, 0.0, 1.0, 1.0, Double.MIN_VALUE };
		gbl.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, Double.MIN_VALUE };
		frame.getContentPane().setLayout(gbl);

		int row = 1;
		if (isNew) {
			addLabel("Name:", 1, row);
			vulnName = new JTextField();
			if (scanIssues != null) {
				vulnName.setText(scanIssues.size() == 1 ? scanIssues.keySet().iterator().next() : "Multiple Issues Selected");
			}
			GridBagConstraints g = fieldConstraints(2, row);
			frame.getContentPane().add(vulnName, g);
			row++;
		}

		addLabel("Assessment:", 1, row);
		assessmentList = new JComboBox<>();
		assessmentList.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				onAssessmentSelected();
			}
		});
		frame.getContentPane().add(assessmentList, fieldConstraints(2, row));
		row++;

		if (!isNew) {
			addLabel("Vulnerability:", 1, row);
			vulnList = new JComboBox<>();
			vulnList.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					onVulnerabilitySelected();
				}
			});
			frame.getContentPane().add(vulnList, fieldConstraints(2, row));
			row++;
		}

		// Default vuln search (new, non-scan only)
		if (isNew && !isScanIssue) {
			JPanel searchPanel = new JPanel(new GridBagLayout());
			searchPanel.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null),
					"Search Default Vulnerabilities", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(59, 59, 59)));
			GridBagConstraints gsp = new GridBagConstraints();
			gsp.gridwidth = 2; gsp.insets = new Insets(0, 0, 5, 5); gsp.fill = GridBagConstraints.BOTH;
			gsp.gridx = 1; gsp.gridy = row;
			frame.getContentPane().add(searchPanel, gsp);

			GridBagConstraints s0 = new GridBagConstraints();
			s0.insets = new Insets(2, 2, 2, 5); s0.anchor = GridBagConstraints.EAST; s0.gridx = 0; s0.gridy = 0;
			searchPanel.add(new JLabel("Search"), s0);
			vulnSearch = new JTextField(16);
			vulnSearch.addKeyListener(new KeyAdapter() {
				@Override
				public void keyReleased(KeyEvent e) {
					doDefaultVulnSearch();
				}
			});
			GridBagConstraints s1 = new GridBagConstraints();
			s1.insets = new Insets(2, 0, 2, 2); s1.fill = GridBagConstraints.HORIZONTAL; s1.weightx = 1.0; s1.gridx = 1; s1.gridy = 0;
			searchPanel.add(vulnSearch, s1);
			defaultVulns = new JComboBox<>();
			defaultVulns.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					onDefaultVulnSelected();
				}
			});
			GridBagConstraints s2 = new GridBagConstraints();
			s2.insets = new Insets(2, 0, 2, 2); s2.fill = GridBagConstraints.HORIZONTAL; s2.gridx = 1; s2.gridy = 1;
			searchPanel.add(defaultVulns, s2);
			row++;
		}

		// Options panel
		JPanel options = new JPanel(new GridBagLayout());
		options.setBorder(new TitledBorder(new LineBorder(new Color(192, 192, 192)), "Options",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(59, 59, 59)));
		GridBagConstraints gop = new GridBagConstraints();
		gop.insets = new Insets(0, 0, 5, 5); gop.gridwidth = 2; gop.fill = GridBagConstraints.BOTH; gop.gridx = 1; gop.gridy = row;
		frame.getContentPane().add(options, gop);

		optReq = new JCheckBox("Request", true);
		optCookies = new JCheckBox("Snip Cookies");
		optResp = new JCheckBox("Response", true);
		useSelected = new JCheckBox("Extract Selection", true);
		options.add(optReq, opt(0, 0));
		options.add(optCookies, opt(1, 0));
		options.add(optResp, opt(0, 1));
		options.add(useSelected, opt(1, 1));

		options.add(new JLabel("Severity:"), opt(2, 0));
		severity = new JComboBox<>();
		String[] severityStrings = factionApi.getSeverityStrings();
		FSUtils.setSeverityComboBoxDefaults(factionApi, severity, FactionAPI.BURP_SEV_HIGH, severityStrings, (s) -> {});
		options.add(severity, opt(3, 0));

		options.add(new JLabel("Section:"), opt(2, 1));
		sections = new JComboBox<>();
		options.add(sections, opt(3, 1));

		row++;

		// Exploit steps editor + image tools
		JPanel stepsPanel = new JPanel(new GridBagLayout());
		stepsPanel.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null),
				"Exploit Steps (Supports Markdown)", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagConstraints gsteps = new GridBagConstraints();
		gsteps.fill = GridBagConstraints.BOTH; gsteps.gridwidth = 2; gsteps.insets = new Insets(0, 0, 5, 5);
		gsteps.gridx = 1; gsteps.gridy = row; gsteps.weighty = 1.0;
		frame.getContentPane().add(stepsPanel, gsteps);

		JButton btnInsertImage = new JButton("Insert Image");
		btnInsertImage.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String aid = selectedAssessmentId();
				if (aid != null) uploadAndInsertImage(aid);
			}
		});
		GridBagConstraints gi = new GridBagConstraints();
		gi.anchor = GridBagConstraints.WEST; gi.insets = new Insets(2, 2, 2, 5); gi.gridx = 0; gi.gridy = 0;
		stepsPanel.add(btnInsertImage, gi);

		JPanel hint = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
		JLabel pasteHint = new JLabel("or paste an image directly to upload it");
		pasteHint.setFont(pasteHint.getFont().deriveFont(Font.ITALIC));
		pasteHint.setForeground(Color.GRAY);
		hint.add(pasteHint);
		imageSpinner = new JProgressBar();
		imageSpinner.setIndeterminate(true);
		imageSpinner.setStringPainted(true);
		imageSpinner.setString("Uploading…");
		imageSpinner.setPreferredSize(new Dimension(110, 18));
		imageSpinner.setVisible(false);
		hint.add(imageSpinner);
		GridBagConstraints gh = new GridBagConstraints();
		gh.anchor = GridBagConstraints.WEST; gh.insets = new Insets(2, 2, 2, 5); gh.gridx = 1; gh.gridy = 0;
		stepsPanel.add(hint, gh);

		message_1 = new JEditorPane();
		message_1.setContentType("text/plain");
		message_1.setText("Enter exploit steps or additional information here");
		message_1.setTransferHandler(new ImagePasteHandler(message_1.getTransferHandler()));
		JScrollPane stepsScroll = new JScrollPane(message_1);
		GridBagConstraints gse = new GridBagConstraints();
		gse.fill = GridBagConstraints.BOTH; gse.gridwidth = 2; gse.insets = new Insets(0, 2, 2, 2);
		gse.gridx = 0; gse.gridy = 1; gse.weightx = 1.0; gse.weighty = 1.0;
		stepsPanel.add(stepsScroll, gse);

		// Custom fields panel (right column)
		customFieldsPanel = new JPanel(new GridBagLayout());
		JScrollPane cfScroll = new JScrollPane(customFieldsPanel);
		cfScroll.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null),
				"Custom Fields", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		cfScroll.getVerticalScrollBar().setUnitIncrement(12);
		GridBagConstraints gcf = new GridBagConstraints();
		gcf.fill = GridBagConstraints.BOTH; gcf.insets = new Insets(0, 0, 5, 5); gcf.gridx = 3; gcf.gridy = row; gcf.weighty = 1.0;
		frame.getContentPane().add(cfScroll, gcf);
		row++;

		btnSave = new JButton("Save");
		btnSave.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				save();
			}
		});
		GridBagConstraints gbs = new GridBagConstraints();
		gbs.fill = GridBagConstraints.HORIZONTAL; gbs.insets = new Insets(0, 0, 5, 5); gbs.gridx = 1; gbs.gridy = row;
		frame.getContentPane().add(btnSave, gbs);

		// Populate assessments
		asmts = factionApi.getAssessments();
		for (int i = 0; i < asmts.size(); i++) {
			JSONObject a = (JSONObject) asmts.get(i);
			assessmentList.addItem(str(a.get("appId")) + " " + str(a.get("name")));
			if (preselectAssessmentId != null && preselectAssessmentId.equals(str(a.get("id")))) {
				assessmentList.setSelectedIndex(i);
			}
		}
		if (assessmentList.getItemCount() > 0 && assessmentList.getSelectedIndex() < 0) {
			assessmentList.setSelectedIndex(0);
		}
		onAssessmentSelected();
	}

	// ── Event handlers ──────────────────────────────────────────────────────────

	private void onAssessmentSelected() {
		JSONObject asmt = selectedAssessment();
		if (asmt == null) return;
		String aid = str(asmt.get("id"));

		// Sections from this assessment
		sections.removeAllItems();
		sections.addItem("");
		Object sectionsArr = asmt.get("sections");
		if (sectionsArr instanceof JSONArray) {
			for (Object s : (JSONArray) sectionsArr) sections.addItem(str(s));
		}

		loadCustomFields(aid);

		if (!isNew) {
			vulns = factionApi.getVulnerabilities(aid);
			vulnList.removeAllItems();
			for (Object o : vulns) vulnList.addItem(str(((JSONObject) o).get("name")));
			btnSave.setEnabled(vulns.size() > 0);
		}
	}

	/**
	 * Existing-finding mode: show the finding's current section and custom-field
	 * values so a save doesn't silently blank them. 2.x keys {@code fieldValues} by
	 * field-definition id (resolved through {@code fieldDefinitions}); 1.x keys them
	 * by variableName directly.
	 */
	private void onVulnerabilitySelected() {
		JSONObject asmt = selectedAssessment();
		int vindex = vulnList == null ? -1 : vulnList.getSelectedIndex();
		if (asmt == null || vindex < 0 || vulns == null || vindex >= vulns.size()) return;
		JSONObject vuln = factionApi.getVulnerability(str(asmt.get("id")), str(((JSONObject) vulns.get(vindex)).get("id")));
		if (vuln == null) return;

		String section = str(vuln.get("section"));
		if (!section.isEmpty() && sections != null) {
			for (int i = 0; i < sections.getItemCount(); i++) {
				if (section.equals(sections.getItemAt(i))) { sections.setSelectedIndex(i); break; }
			}
		}

		Object valuesObj = vuln.get("fieldValues");
		if (!(valuesObj instanceof JSONObject)) return;
		JSONObject values = (JSONObject) valuesObj;
		Map<String, String> variableNameById = new HashMap<>();
		Object defs = vuln.get("fieldDefinitions");
		if (defs instanceof JSONArray) {
			for (Object o : (JSONArray) defs) {
				JSONObject def = (JSONObject) o;
				variableNameById.put(str(def.get("id")), str(def.get("variableName")));
			}
		}
		for (Object k : values.keySet()) {
			String key = str(k);
			String variableName = variableNameById.getOrDefault(key, key);
			Component comp = customFieldComponents.get(variableName);
			String value = str(values.get(k));
			if (comp instanceof JComboBox) {
				@SuppressWarnings("unchecked")
				JComboBox<String> combo = (JComboBox<String>) comp;
				boolean found = false;
				for (int i = 0; i < combo.getItemCount(); i++) if (value.equals(combo.getItemAt(i))) { found = true; break; }
				if (!found && !value.isEmpty()) combo.addItem(value);
				combo.setSelectedItem(value);
			} else if (comp instanceof JTextField) {
				((JTextField) comp).setText(value);
			}
		}
	}

	private void doDefaultVulnSearch() {
		if (vulnSearch.getText().length() < 2) {
			defaultVulns.removeAllItems();
			defaultVulnsByName.clear();
			return;
		}
		JSONArray results = factionApi.searchDefaultVulns(vulnSearch.getText());
		defaultVulns.removeAllItems();
		defaultVulnsByName.clear();
		for (Object o : results) {
			JSONObject dv = (JSONObject) o;
			String name = str(dv.get("name"));
			defaultVulns.addItem(name);
			defaultVulnsByName.put(name, dv);
		}
	}

	private void onDefaultVulnSelected() {
		Object sel = defaultVulns.getSelectedItem();
		if (sel == null) return;
		JSONObject dv = defaultVulnsByName.get(sel.toString());
		if (dv == null) return;
		if (vulnName != null) vulnName.setText(str(dv.get("name")));
		selectSeverity(str(dv.get("severity")));
	}

	private void selectSeverity(String sev) {
		if (sev == null) return;
		for (int i = 0; i < severity.getItemCount(); i++) {
			if (severity.getItemAt(i).equalsIgnoreCase(sev)) {
				severity.setSelectedIndex(i);
				return;
			}
		}
	}

	// ── Save flows ──────────────────────────────────────────────────────────────

	@SuppressWarnings("unchecked")
	private void save() {
		try {
			JSONObject asmt = selectedAssessment();
			if (asmt == null) {
				JOptionPane.showMessageDialog(frame, "Select an assessment first.", "Faction", JOptionPane.WARNING_MESSAGE);
				return;
			}
			String aid = str(asmt.get("id"));

			if (isNew && isScanIssue) {
				saveScanIssues(aid);
			} else if (isNew) {
				saveNewFinding(aid);
			} else {
				saveToExisting(aid);
			}
			frame.dispose();
		} catch (Exception ex) {
			ex.printStackTrace();
			JOptionPane.showMessageDialog(frame, "Error saving to Faction: " + ex.getMessage(), "Faction", JOptionPane.ERROR_MESSAGE);
		}
	}

	@SuppressWarnings("unchecked")
	private void saveNewFinding(String aid) {
		String details = createMessage((ContextMenuEvent) event);
		JSONObject body = new JSONObject();
		body.put("name", vulnName.getText());
		body.put("severity", "" + severity.getSelectedItem());
		body.put("details", details);

		// Seed from a chosen default vulnerability, if any.
		if (defaultVulns != null && defaultVulns.getSelectedItem() != null) {
			JSONObject dv = defaultVulnsByName.get(defaultVulns.getSelectedItem().toString());
			if (dv != null) {
				putIfPresent(body, "defaultVulnerabilityId", dv.get("defaultVulnerabilityId"));
				putIfPresent(body, "description", dv.get("description"));
				putIfPresent(body, "recommendation", dv.get("recommendation"));
				putIfPresent(body, "likelihood", dv.get("likelihood"));
				putIfPresent(body, "impact", dv.get("impact"));
				putIfPresent(body, "vulnerabilityCategoryId", dv.get("vulnerabilityCategoryId"));
				// Prefer CVSS 4.0, fall back to 3.1
				Object cvssString = dv.get("cvssString40") != null ? dv.get("cvssString40") : dv.get("cvssString31");
				Object cvssScore = dv.get("cvssScore40") != null ? dv.get("cvssScore40") : dv.get("cvssScore31");
				putIfPresent(body, "cvssString", cvssString);
				if (cvssScore != null) body.put("cvssScore", cvssScore);
			}
		}
		String section = sectionValue();
		if (!section.isEmpty()) body.put("section", section);

		factionApi.createVulnerabilityWithFields(aid, body, customFieldValues());
	}

	@SuppressWarnings("unchecked")
	private void saveScanIssues(String aid) {
		Iterator<String> it = scanIssues.keySet().iterator();
		while (it.hasNext()) {
			List<AuditIssue> issues = scanIssues.get(it.next());
			AuditIssue base = issues.get(0);

			LinkedHashMap<String, String> supporting = new LinkedHashMap<>();
			StringBuilder details = new StringBuilder("<b><u>Affected URLs:</u></b>\n<ul>\n");
			for (AuditIssue issue : issues) {
				details.append("<li>").append(issue.baseUrl()).append("</li>\n");
				if (issue.detail() != null) supporting.put(FSUtils.hashText(issue.detail()), issue.detail());
			}
			details.append("</ul>\n");
			StringBuilder supportingText = new StringBuilder();
			for (Entry<String, String> e : supporting.entrySet()) supportingText.append(e.getValue()).append("\n");
			String detailHtml = supportingText + details.toString() + createScanMessage(base);

			JSONObject body = new JSONObject();
			body.put("name", base.name());
			body.put("severity", factionApi.getSevMapping(base.severity().name()));
			putIfPresent(body, "description", base.definition().background());
			putIfPresent(body, "recommendation", "" + base.definition().remediation());
			body.put("details", detailHtml);
			String section = sectionValue();
			if (!section.isEmpty()) body.put("section", section);

			factionApi.createVulnerabilityWithFields(aid, body, customFieldValues());
		}
	}

	private void saveToExisting(String aid) {
		int vindex = vulnList.getSelectedIndex();
		if (vindex < 0 || vulns == null || vindex >= vulns.size()) return;
		JSONObject vuln = (JSONObject) vulns.get(vindex);
		String vid = str(vuln.get("id"));

		String details = createMessage((ContextMenuEvent) event);
		factionApi.appendDetails(aid, vid, details, "" + severity.getSelectedItem());

		String section = sectionValue();
		if (!section.isEmpty()) factionApi.setSection(aid, vid, section);

		Map<String, String> cf = customFieldValues();
		if (!cf.isEmpty()) factionApi.setCustomFieldValues(aid, vid, cf);
	}


	// ── HTML message building ───────────────────────────────────────────────────

	/** Builds the details HTML: the markdown exploit steps + request/response. */
	private String createMessage(ContextMenuEvent event) {
		String message = markdownToHtml(getMessage().getText());
		StringBuilder out = new StringBuilder(message);

		Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
		HttpRequestResponse reqres = null;
		SelectionContext selectionContext = null;
		int selStart = -1, selEnd = -1;
		if (editor.isPresent()) {
			reqres = editor.get().requestResponse();
			if (useSelected != null && useSelected.isSelected() && editor.get().selectionOffsets().isPresent()) {
				selStart = editor.get().selectionOffsets().get().startIndexInclusive();
				selEnd = editor.get().selectionOffsets().get().endIndexExclusive();
				selectionContext = editor.get().selectionContext();
			}
		} else if (!event.selectedRequestResponses().isEmpty()) {
			reqres = event.selectedRequestResponses().get(0);
		}
		if (reqres == null) return out.toString();

		// ISO-8859-1 keeps one char per byte, so Burp's byte offsets index the string directly.
		CodeBlockHtml.Excerpt request = null, response = null;
		if (optReq.isSelected() && reqres.request() != null) {
			String full = new String(reqres.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
			request = selectionContext == SelectionContext.REQUEST && selStart >= 0 && selEnd > selStart
					? CodeBlockHtml.excerpt(full, selStart, selEnd) : CodeBlockHtml.whole(full);
		}
		if (optResp.isSelected() && reqres.hasResponse()) {
			String full = new String(reqres.response().toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
			response = selectionContext == SelectionContext.RESPONSE && selStart >= 0 && selEnd > selStart
					? CodeBlockHtml.excerpt(full, selStart, selEnd) : CodeBlockHtml.whole(full);
		}
		if (optCookies.isSelected()) {
			if (request != null) request = snipCookies(request, "Cookie: ");
			if (response != null) response = snipCookies(response, "Set-Cookie: ");
		}
		// Post markup the way Burp's Pretty view showed it, not as the raw one-liner.
		if (request != null) request = HtmlPretty.apply(request);
		if (response != null) response = HtmlPretty.apply(response);
		if (request != null && !request.lines().isEmpty()) out.append(CodeBlockHtml.block("Request", request));
		if (response != null && !response.lines().isEmpty()) out.append(CodeBlockHtml.block("Response", response));
		return out.toString();
	}

	/** Scan-issue variant: markdown steps + the base issue's request/response, numbered from 1. */
	private String createScanMessage(AuditIssue issue) {
		StringBuilder out = new StringBuilder(markdownToHtml(getMessage().getText()));
		if (issue.requestResponses() != null && !issue.requestResponses().isEmpty()) {
			HttpRequestResponse reqres = issue.requestResponses().get(0);
			if (optReq.isSelected() && reqres.request() != null) {
				CodeBlockHtml.Excerpt req = CodeBlockHtml.whole(
						new String(reqres.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1));
				if (optCookies.isSelected()) req = snipCookies(req, "Cookie: ");
				out.append(CodeBlockHtml.block("Request", HtmlPretty.apply(req)));
			}
			if (optResp.isSelected() && reqres.hasResponse()) {
				CodeBlockHtml.Excerpt resp = CodeBlockHtml.whole(
						new String(reqres.response().toByteArray().getBytes(), StandardCharsets.ISO_8859_1));
				if (optCookies.isSelected()) resp = snipCookies(resp, "Set-Cookie: ");
				out.append(CodeBlockHtml.block("Response", HtmlPretty.apply(resp)));
			}
		}
		return out.toString();
	}

	/** Replaces the value of every header line starting with {@code prefix} with a snip marker. */
	private static CodeBlockHtml.Excerpt snipCookies(CodeBlockHtml.Excerpt e, String prefix) {
		return e.withLines(line -> line.regionMatches(true, 0, prefix, 0, prefix.length())
				? prefix + CodeBlockHtml.SNIP_MARKER : line);
	}

	private static String markdownToHtml(String md) {
		Parser parser = Parser.builder().build();
		Node document = parser.parse(md == null ? "" : md);
		HtmlRenderer renderer = HtmlRenderer.builder().build();
		String html = renderer.render(document);
		return html.replaceAll("</p>", "<br/>");
	}

	// ── Custom fields ───────────────────────────────────────────────────────────

	private void loadCustomFields(String aid) {
		customFieldComponents.clear();
		customFieldDefs.clear();
		customFieldsPanel.removeAll();
		JSONArray fields = factionApi.getVulnerabilityFields(aid);
		int row = 0;
		if (fields != null) {
			for (Object o : fields) {
				JSONObject f = (JSONObject) o;
				String variableName = str(f.get("variableName"));
				String display = f.get("displayName") == null ? variableName : str(f.get("displayName"));
				String fieldType = f.get("fieldType") == null ? "STRING" : str(f.get("fieldType"));
				if (variableName.isEmpty() || fieldType.equalsIgnoreCase("RICH_TEXT")) continue;

				JLabel label = new JLabel(display + ":");
				GridBagConstraints lg = new GridBagConstraints();
				lg.anchor = GridBagConstraints.WEST; lg.insets = new Insets(2, 2, 2, 5); lg.gridx = 0; lg.gridy = row;
				customFieldsPanel.add(label, lg);

				Component comp = createCustomFieldComponent(f);
				GridBagConstraints cg = new GridBagConstraints();
				cg.fill = GridBagConstraints.HORIZONTAL; cg.weightx = 1.0; cg.insets = new Insets(2, 0, 2, 2); cg.gridx = 1; cg.gridy = row;
				customFieldsPanel.add(comp, cg);

				customFieldComponents.put(variableName, comp);
				customFieldDefs.put(variableName, f);
				row++;
			}
		}
		GridBagConstraints filler = new GridBagConstraints();
		filler.gridx = 0; filler.gridy = row; filler.gridwidth = 2; filler.weighty = 1.0; filler.fill = GridBagConstraints.BOTH;
		customFieldsPanel.add(Box.createGlue(), filler);
		customFieldsPanel.revalidate();
		customFieldsPanel.repaint();
	}

	private Component createCustomFieldComponent(JSONObject f) {
		String fieldType = f.get("fieldType") == null ? "STRING" : str(f.get("fieldType"));
		String defaultValue = f.get("defaultValue") == null ? "" : str(f.get("defaultValue"));
		if (fieldType.equalsIgnoreCase("DROPDOWN")) {
			JComboBox<String> combo = new JComboBox<>();
			combo.addItem("");
			Object opts = f.get("dropdownOptions");
			if (opts instanceof JSONArray) {
				for (Object opt : (JSONArray) opts) {
					if (opt != null && !opt.toString().trim().isEmpty()) combo.addItem(opt.toString());
				}
			}
			if (!defaultValue.isEmpty()) combo.setSelectedItem(defaultValue);
			return combo;
		}
		JTextField tf = new JTextField(defaultValue, 12);
		return tf;
	}

	/** Custom field values keyed by variableName (empty values omitted). */
	private Map<String, String> customFieldValues() {
		Map<String, String> out = new HashMap<>();
		for (Entry<String, Component> e : customFieldComponents.entrySet()) {
			Component comp = e.getValue();
			String value = "";
			if (comp instanceof JComboBox) {
				Object sel = ((JComboBox<?>) comp).getSelectedItem();
				value = sel == null ? "" : sel.toString();
			} else if (comp instanceof JTextField) {
				value = ((JTextField) comp).getText();
			}
			if (value != null && !value.isEmpty()) out.put(e.getKey(), value);
		}
		return out;
	}

	/** Selected report section, or "" for the implicit default. */
	private String sectionValue() {
		if (sections == null || sections.getSelectedItem() == null) return "";
		String section = sections.getSelectedItem().toString();
		if (section.isEmpty() || section.equalsIgnoreCase("Default")) return "";
		return section;
	}

	// ── Image upload ────────────────────────────────────────────────────────────

	private void uploadAndInsertImage(String aid) {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Select an Image to Upload");
		chooser.setFileFilter(new FileNameExtensionFilter("Images (png, jpg, jpeg, gif, bmp, webp)", "png", "jpg", "jpeg", "gif", "bmp", "webp"));
		if (chooser.showOpenDialog(frame) != JFileChooser.APPROVE_OPTION) return;
		File file = chooser.getSelectedFile();
		try {
			byte[] bytes = Files.readAllBytes(file.toPath());
			String mime = Files.probeContentType(file.toPath());
			if (mime == null || !mime.startsWith("image")) mime = mimeFromName(file.getName());
			uploadImageBytesAndInsert(bytes, file.getName(), mime, aid);
		} catch (Exception ex) {
			JOptionPane.showMessageDialog(frame, "Error uploading image: " + ex.getMessage(), "Upload Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	private void uploadImageBytesAndInsert(final byte[] bytes, final String filename, final String mime, final String aid) {
		setImageUploading(true);
		SwingWorker<String, Void> worker = new SwingWorker<String, Void>() {
			protected String doInBackground() {
				return factionApi.uploadInlineImage(aid, bytes, filename, mime);
			}
			protected void done() {
				setImageUploading(false);
				try {
					String url = get();
					if (url == null || url.isEmpty()) {
						JOptionPane.showMessageDialog(frame, "Image upload failed.", "Upload Failed", JOptionPane.ERROR_MESSAGE);
						return;
					}
					String markdown = "![evidence](" + url + ")";
					int pos = message_1.getCaretPosition();
					message_1.getDocument().insertString(pos, markdown, null);
					message_1.setCaretPosition(pos + markdown.length());
					message_1.requestFocusInWindow();
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(frame, "Error uploading image: " + ex.getMessage(), "Upload Error", JOptionPane.ERROR_MESSAGE);
				}
			}
		};
		worker.execute();
	}

	private void setImageUploading(boolean uploading) {
		if (imageSpinner != null) imageSpinner.setVisible(uploading);
	}

	private class ImagePasteHandler extends TransferHandler {
		private final TransferHandler delegate;
		ImagePasteHandler(TransferHandler delegate) { this.delegate = delegate; }

		@Override
		public boolean canImport(TransferSupport support) {
			if (support.isDataFlavorSupported(DataFlavor.imageFlavor)) return true;
			return delegate != null && delegate.canImport(support);
		}

		@Override
		public boolean importData(TransferSupport support) {
			if (support.isDataFlavorSupported(DataFlavor.imageFlavor)) {
				String aid = selectedAssessmentId();
				if (aid == null) {
					JOptionPane.showMessageDialog(frame, "Select an assessment before pasting an image.", "No Assessment", JOptionPane.WARNING_MESSAGE);
					return true;
				}
				try {
					Image img = (Image) support.getTransferable().getTransferData(DataFlavor.imageFlavor);
					BufferedImage buffered = toBufferedImage(img);
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					ImageIO.write(buffered, "png", baos);
					uploadImageBytesAndInsert(baos.toByteArray(), "evidence.png", "image/png", aid);
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(frame, "Error uploading pasted image: " + ex.getMessage(), "Upload Error", JOptionPane.ERROR_MESSAGE);
				}
				return true;
			}
			return delegate != null && delegate.importData(support);
		}

		@Override
		public int getSourceActions(JComponent c) {
			return delegate != null ? delegate.getSourceActions(c) : NONE;
		}

		@Override
		protected Transferable createTransferable(JComponent c) {
			return delegate != null ? null : super.createTransferable(c);
		}
	}

	private static BufferedImage toBufferedImage(Image img) {
		if (img instanceof BufferedImage) return (BufferedImage) img;
		int w = Math.max(1, img.getWidth(null));
		int h = Math.max(1, img.getHeight(null));
		BufferedImage buffered = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = buffered.createGraphics();
		g.drawImage(img, 0, 0, null);
		g.dispose();
		return buffered;
	}

	private String mimeFromName(String name) {
		String n = name.toLowerCase();
		if (n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
		if (n.endsWith(".gif")) return "image/gif";
		if (n.endsWith(".bmp")) return "image/bmp";
		if (n.endsWith(".webp")) return "image/webp";
		if (n.endsWith(".svg")) return "image/svg+xml";
		return "image/png";
	}

	// ── Small helpers ───────────────────────────────────────────────────────────

	private JSONObject selectedAssessment() {
		int index = assessmentList.getSelectedIndex();
		if (index < 0 || asmts == null || index >= asmts.size()) return null;
		return (JSONObject) asmts.get(index);
	}

	private String selectedAssessmentId() {
		JSONObject a = selectedAssessment();
		return a == null ? null : str(a.get("id"));
	}

	private void addLabel(String text, int gridx, int gridy) {
		JLabel lbl = new JLabel(text);
		GridBagConstraints g = new GridBagConstraints();
		g.anchor = GridBagConstraints.EAST; g.insets = new Insets(0, 0, 5, 5); g.gridx = gridx; g.gridy = gridy;
		frame.getContentPane().add(lbl, g);
	}

	private GridBagConstraints fieldConstraints(int gridx, int gridy) {
		GridBagConstraints g = new GridBagConstraints();
		g.fill = GridBagConstraints.HORIZONTAL; g.insets = new Insets(0, 0, 5, 5); g.gridx = gridx; g.gridy = gridy;
		return g;
	}

	private GridBagConstraints opt(int gridx, int gridy) {
		GridBagConstraints g = new GridBagConstraints();
		g.anchor = GridBagConstraints.WEST; g.insets = new Insets(2, 4, 2, 8); g.gridx = gridx; g.gridy = gridy;
		return g;
	}

	@SuppressWarnings("unchecked")
	private static void putIfPresent(JSONObject o, String key, Object value) {
		if (value != null && !value.toString().isEmpty()) o.put(key, value);
	}

	private static String str(Object o) {
		return o == null ? "" : o.toString();
	}

	public JEditorPane getMessage() {
		return message_1;
	}
}
