package com.faction.gui;

import java.awt.Color;
import com.faction.utils.ImageCache;
import java.awt.Cursor;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import com.faction.utils.FindingHistory;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.faction.api.FactionAPI;
import com.faction.utils.FSUtils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;

/**
 * The Faction suite tab. Three sub-tabs:
 *  - Queues: active assessments and scheduled retests, polled on a timer.
 *  - Assessment: the selected assessment's details and its findings.
 *  - Config: server URL, API key, refresh interval, and Burp→Faction severity map.
 */
public class FactionGUI extends JPanel implements ExtensionUnloadingHandler {

	private final FactionAPI factionApi;
	private final MontoyaApi montoya;
	private final Logging logging;

	private JComboBox<String> versionBox;
	private JPanel configPanel;
	private final List<JComponent> severityRows = new ArrayList<>();
	private JTextField serverTxt;
	private JPasswordField tokenTxt;
	private JTextField refreshRate;
	private JLabel testResult;

	private FactionTableModel asmtModel;
	private FactionTableModel vulnModel;
	private FactionTableModel verModel;
	private JTable queueTable;
	private JTable verTable;
	private JTable vulnTable;
	private JTextField asmtName;
	private JEditorPane scopeTxt;

	private Timer refreshTimer;
	private String selectedAssessmentId = "";
	private String selectedAssessmentName = "";
	/** Finalised findings from the application's other assessments; reloaded on selection only. */
	private volatile List<FindingHistory.Row> historyRows = Collections.emptyList();
	/** Bumped per selection so a slow history load for a previous one is discarded. */
	private final AtomicInteger selectionSerial = new AtomicInteger();

	// Column indexes for the assessment queue model
	private static final String[] ASMT_COLS = { "AppId", "Name", "Application", "Status", "Start", "End", "Id" };
	private static final int ASMT_ID = 6;
	// Retest (verification) queue model
	private static final String[] VER_COLS = { "Start", "Assessment", "Vulnerability", "Severity", "Status", "VulnId", "AssessmentId" };
	private static final int VER_VULN_ID = 5;
	private static final int VER_ASMT_ID = 6;
	// Findings model
	private static final String[] VULN_COLS = { "Name", "Severity", "Status", "Assessment", "Opened", "Closed", "vid", "aid" };
	private static final int VULN_ID = 6;
	private static final int VULN_AID = 7;

	public FactionGUI(MontoyaApi api) {
		this.montoya = api;
		this.factionApi = new FactionAPI(api);
		this.logging = api.logging();

		setBorder(new EmptyBorder(5, 5, 5, 5));
		setLayout(new GridLayout(1, 0, 0, 0));

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);

		tabbedPane.addTab("Queues", null, buildQueuesTab(), null);
		tabbedPane.addTab("Assessment", null, buildAssessmentTab(), null);
		tabbedPane.addTab("Config", null, buildConfigTab(), null);

		startTimer();
	}

	// ── Queues tab ──────────────────────────────────────────────────────────────

	private JComponent buildQueuesTab() {
		JSplitPane split = new JSplitPane();
		split.setResizeWeight(0.5);

		// Left: assessments
		asmtModel = new FactionTableModel(ASMT_COLS);
		queueTable = new JTable(asmtModel);
		queueTable.setAutoCreateRowSorter(true);
		queueTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			public void valueChanged(ListSelectionEvent event) {
				if (!event.getValueIsAdjusting() && queueTable.getSelectedRow() != -1) {
					int row = queueTable.convertRowIndexToModel(queueTable.getSelectedRow());
					selectAssessment("" + asmtModel.getValueAt(row, ASMT_ID),
							"" + asmtModel.getValueAt(row, 0),
							"" + asmtModel.getValueAt(row, 1),
							"" + asmtModel.getValueAt(row, 2));
				}
			}
		});
		JPanel left = new JPanel(new java.awt.BorderLayout());
		left.add(new JScrollPane(queueTable), java.awt.BorderLayout.CENTER);
		JPanel leftBtns = new JPanel();
		JButton refreshAsmt = new JButton("Refresh");
		refreshAsmt.addActionListener(e -> updateAPI());
		leftBtns.add(refreshAsmt);
		leftBtns.add(new JLabel("Select an assessment to load the Assessment tab"));
		left.add(leftBtns, java.awt.BorderLayout.SOUTH);
		split.setLeftComponent(left);

		// Right: retests
		verModel = new FactionTableModel(VER_COLS);
		verTable = new JTable(verModel);
		verTable.setAutoCreateRowSorter(true);
		verTable.setDefaultRenderer(Object.class, new CustomCellRenderer());
		verTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && !e.isConsumed()) {
					e.consume();
					int r = verTable.rowAtPoint(e.getPoint());
					if (r >= 0) {
						int row = verTable.convertRowIndexToModel(r);
						openVulnerability("" + verModel.getValueAt(row, VER_ASMT_ID),
								"" + verModel.getValueAt(row, VER_VULN_ID));
					}
				}
			}
		});
		JPanel right = new JPanel(new java.awt.BorderLayout());
		right.add(new JScrollPane(verTable), java.awt.BorderLayout.CENTER);
		JPanel rightBtns = new JPanel();
		JButton refreshVer = new JButton("Refresh");
		refreshVer.addActionListener(e -> updateAPI());
		rightBtns.add(refreshVer);
		rightBtns.add(new JLabel("Double-click a retest to view its vulnerability"));
		right.add(rightBtns, java.awt.BorderLayout.SOUTH);
		split.setRightComponent(right);

		return split;
	}

	// ── Assessment tab ──────────────────────────────────────────────────────────

	private JComponent buildAssessmentTab() {
		JPanel asmtPanel = new JPanel(new GridLayout(2, 1, 0, 0));

		JPanel top = new JPanel(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.insets = new Insets(4, 6, 4, 6);
		c.anchor = GridBagConstraints.WEST;

		JLabel lblName = new JLabel("Name:");
		lblName.setFont(new Font("Arial", Font.BOLD, 16));
		c.gridx = 0; c.gridy = 0;
		top.add(lblName, c);

		asmtName = new JTextField();
		asmtName.setFont(new Font("Arial", Font.BOLD, 14));
		asmtName.setEditable(false);
		c.gridx = 1; c.gridy = 0; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0;
		top.add(asmtName, c);

		JPanel scopePanel = new JPanel(new java.awt.BorderLayout());
		scopePanel.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)),
				"Assessment Scope", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(51, 51, 51)));
		scopeTxt = new JEditorPane();
		scopeTxt.setEditable(false);
		scopeTxt.setEditorKitForContentType("text/html", new Base64HtmlEditor(factionApi));
		scopeTxt.setContentType("text/html");
		scopePanel.add(new JScrollPane(scopeTxt), java.awt.BorderLayout.CENTER);
		c.gridx = 0; c.gridy = 1; c.gridwidth = 2; c.fill = GridBagConstraints.BOTH; c.weighty = 1.0;
		top.add(scopePanel, c);

		asmtPanel.add(top);

		vulnModel = new FactionTableModel(VULN_COLS);
		vulnTable = new JTable(vulnModel);
		vulnTable.setAutoCreateRowSorter(true);
		vulnTable.setDefaultRenderer(Object.class, new CustomCellRenderer());
		vulnTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && !e.isConsumed()) {
					e.consume();
					int r = vulnTable.rowAtPoint(e.getPoint());
					if (r >= 0) {
						int modelRow = vulnTable.convertRowIndexToModel(r);
						openVulnerability("" + vulnModel.getValueAt(modelRow, VULN_AID),
								"" + vulnModel.getValueAt(modelRow, VULN_ID));
					}
				}
			}
		});
		// The id columns drive double-click but are not for reading; keep them in the model only.
		vulnTable.removeColumn(vulnTable.getColumnModel().getColumn(VULN_AID));
		vulnTable.removeColumn(vulnTable.getColumnModel().getColumn(VULN_ID));
		asmtPanel.add(new JScrollPane(vulnTable));

		return asmtPanel;
	}

	// ── Config tab ──────────────────────────────────────────────────────────────

	private JComponent buildConfigTab() {
		JPanel panel = new JPanel(null);
		configPanel = panel;

		JLabel lblHeader = new JLabel("Server Configuration");
		lblHeader.setFont(new Font("Lucida Grande", Font.BOLD, 18));
		lblHeader.setBounds(32, 20, 392, 24);
		panel.add(lblHeader);

		JLabel lblVersion = new JLabel("Faction Version:");
		lblVersion.setBounds(32, 58, 100, 20);
		panel.add(lblVersion);
		versionBox = new JComboBox<>(new String[] { VERSION_LABEL_1, VERSION_LABEL_2 });
		versionBox.setSelectedIndex(factionApi.getApiVersion() == FactionAPI.VERSION_1 ? 0 : 1);
		versionBox.setToolTipText("1.x: the original Faction API (FACTION-API-KEY header). 2.x: the /api/v1 REST API (bearer sk_fac_ key).");
		versionBox.setBounds(140, 54, 200, 27);
		panel.add(versionBox);

		JLabel lblServer = new JLabel("Server:");
		lblServer.setBounds(32, 97, 60, 20);
		panel.add(lblServer);
		serverTxt = new JTextField(factionApi.getServer());
		serverTxt.setBounds(140, 93, 360, 27);
		panel.add(serverTxt);

		JLabel lblToken = new JLabel("API Key:");
		lblToken.setBounds(32, 136, 70, 20);
		panel.add(lblToken);
		tokenTxt = new JPasswordField(factionApi.getToken());
		tokenTxt.setBounds(140, 132, 360, 27);
		panel.add(tokenTxt);

		JLabel lblRefresh = new JLabel("Refresh:");
		lblRefresh.setBounds(32, 175, 70, 20);
		panel.add(lblRefresh);
		refreshRate = new JTextField("" + factionApi.getRefresh());
		refreshRate.setBounds(140, 171, 60, 27);
		panel.add(refreshRate);
		JLabel lblSecs = new JLabel("seconds");
		lblSecs.setBounds(208, 175, 80, 20);
		panel.add(lblSecs);

		JButton updateBtn = new JButton("Save");
		updateBtn.setBounds(140, 211, 110, 28);
		updateBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				factionApi.updateProps(selectedVersion(), serverTxt.getText(), new String(tokenTxt.getPassword()), refreshRate.getText());
				factionApi.clearCaches();
				serverTxt.setText(factionApi.getServer());
				testResult.setText("");
				rebuildSeverityRows();
				startTimer();
				updateAPI();
			}
		});
		panel.add(updateBtn);

		JButton testBtn = new JButton("Test Connection");
		testBtn.setBounds(260, 211, 150, 28);
		testBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				factionApi.updateProps(selectedVersion(), serverTxt.getText(), new String(tokenTxt.getPassword()), refreshRate.getText());
				factionApi.clearCaches();
				String err = factionApi.testConnection();
				if (err == null) {
					testResult.setForeground(new Color(0x00A65A));
					testResult.setText("Connected ✓");
				} else {
					testResult.setForeground(new Color(0xDD4B39));
					testResult.setText(err);
				}
			}
		});
		panel.add(testBtn);

		testResult = new JLabel("");
		testResult.setBounds(420, 211, 600, 28);
		panel.add(testResult);

		JLabel lblMap = new JLabel("Burp → Faction Severity Mapping");
		lblMap.setFont(new Font("Lucida Grande", Font.BOLD, 16));
		lblMap.setBounds(32, 263, 420, 26);
		panel.add(lblMap);

		rebuildSeverityRows();

		JLabel lblProject = new JLabel("Faction — Open Source Assessment Collaboration");
		lblProject.setFont(new Font("Lucida Grande", Font.BOLD, 16));
		lblProject.setBounds(560, 20, 520, 24);
		panel.add(lblProject);

		JButton btnGithub = new JButton("https://github.com/factionsecurity/faction");
		btnGithub.setBounds(560, 58, 440, 26);
		btnGithub.addActionListener(e -> browse("https://github.com/factionsecurity/faction"));
		panel.add(btnGithub);

		JButton btnFaction = new JButton("https://www.factionsecurity.com");
		btnFaction.setBounds(560, 92, 440, 26);
		btnFaction.addActionListener(e -> browse("https://www.factionsecurity.com"));
		panel.add(btnFaction);

		return panel;
	}

	private static final String VERSION_LABEL_1 = "Faction 1.x";
	private static final String VERSION_LABEL_2 = "Faction 2.x";

	private int selectedVersion() {
		return versionBox != null && versionBox.getSelectedIndex() == 0 ? FactionAPI.VERSION_1 : FactionAPI.VERSION_2;
	}

	/**
	 * (Re)creates the four Burp→Faction severity rows. The option list depends on
	 * the API generation — 2.x has a fixed enum, 1.x asks the server for its risk
	 * levels — so this runs on first build and again after every Save.
	 */
	private void rebuildSeverityRows() {
		for (JComponent c : severityRows) configPanel.remove(c);
		severityRows.clear();
		String[] sev = factionApi.getSeverityStrings();
		addSeverityRow(configPanel, "Burp HIGH", FactionAPI.BURP_SEV_HIGH, sev, 301);
		addSeverityRow(configPanel, "Burp MEDIUM", FactionAPI.BURP_SEV_MED, sev, 335);
		addSeverityRow(configPanel, "Burp LOW", FactionAPI.BURP_SEV_LOW, sev, 369);
		addSeverityRow(configPanel, "Burp INFORMATION", FactionAPI.BURP_SEV_INFO, sev, 403);
		configPanel.revalidate();
		configPanel.repaint();
	}

	private void addSeverityRow(JPanel panel, String label, String burpKey, String[] sev, int y) {
		JLabel lbl = new JLabel(label);
		lbl.setBounds(200, y + 4, 180, 20);
		panel.add(lbl);
		JComboBox<String> combo = new JComboBox<>();
		FSUtils.setSeverityComboBoxDefaults(factionApi, combo, burpKey, sev,
				(selected) -> factionApi.updateSev(burpKey, selected));
		combo.setBounds(32, y, 150, 27);
		panel.add(combo);
		severityRows.add(lbl);
		severityRows.add(combo);
	}

	private void browse(String url) {
		try {
			Desktop.getDesktop().browse(new java.net.URL(url).toURI());
		} catch (IOException | URISyntaxException ex) {
			logging.logToError("Faction: could not open browser: " + ex);
		}
	}

	// ── Selection / detail loading ──────────────────────────────────────────────

	private void selectAssessment(String assessmentId, String appId, String name, String application) {
		this.selectedAssessmentId = assessmentId;
		this.selectedAssessmentName = name;
		this.historyRows = Collections.emptyList();
		asmtName.setText(appId + " — " + name + (application.isEmpty() ? "" : " (" + application + ")"));
		final int serial = selectionSerial.incrementAndGet();
		// Network off the EDT: the history is one request per sibling assessment.
		Thread t = new Thread(() -> {
			JSONObject asmt = factionApi.getAssessment(assessmentId);
			final String scope = asmt == null || asmt.get("scope") == null ? "" : asmt.get("scope").toString();
			final String applicationId = asmt == null ? "" : str(asmt.get("applicationId"));
			onEdt(() -> {
				if (serial != selectionSerial.get()) return;
				scopeTxt.setText(VulnerabilityDetailsPane.contentHtml(scope));
				scopeTxt.setCaretPosition(0);
			});
			loadFindings(assessmentId); // own findings first, so the table fills quickly
			List<FindingHistory.Row> history = FindingHistory.siblingRows(loadSiblings(applicationId, assessmentId));
			if (serial != selectionSerial.get()) return;
			historyRows = history;
			loadFindings(assessmentId);
		}, "faction-assessment-load");
		t.setDaemon(true);
		t.start();
	}

	/** The application's other assessments with their findings. */
	private List<FindingHistory.Sibling> loadSiblings(String applicationId, String excludeAssessmentId) {
		List<FindingHistory.Sibling> out = new ArrayList<>();
		for (Object o : factionApi.getAssessmentsForApplication(applicationId)) {
			JSONObject a = (JSONObject) o;
			String id = str(a.get("id"));
			if (id.isEmpty() || id.equals(excludeAssessmentId)) continue;
			out.add(new FindingHistory.Sibling(id, str(a.get("name")), factionApi.getVulnerabilities(id)));
		}
		return out;
	}

	/**
	 * Fills the findings table: the assessment's own findings, then the
	 * application's history. Fetches on the calling thread; applies on the EDT.
	 */
	private void loadFindings(String assessmentId) {
		JSONArray own = factionApi.getVulnerabilities(assessmentId);
		List<FindingHistory.Row> rows = new ArrayList<>(FindingHistory.ownRows(assessmentId, selectedAssessmentName, own));
		rows.addAll(historyRows);
		Runnable apply = () -> {
			if (!assessmentId.equals(selectedAssessmentId)) return;
			for (int i = vulnModel.getRowCount() - 1; i >= 0; i--) vulnModel.removeRow(i);
			for (FindingHistory.Row r : rows) {
				Vector<Object> row = new Vector<>();
				row.add(r.name());
				row.add(r.severity());
				row.add(r.status());
				row.add(r.assessmentName());
				row.add(r.openedAt());
				row.add(r.closedAt());
				row.add(r.vulnId());
				row.add(r.assessmentId());
				vulnModel.addRow(row);
			}
		};
		onEdt(apply);
	}

	/**
	 * Opens the details window. The finding and its inline images are fetched
	 * on a background thread — images in parallel, into {@link ImageCache} — so
	 * Burp stays responsive and the window opens after roughly one round trip
	 * rather than one per image.
	 */
	private void openVulnerability(String assessmentId, String vulnId) {
		if (vulnId == null || vulnId.isEmpty()) return; // 1.x retests carry no assessment id; the client copes
		setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
		Thread t = new Thread(() -> {
			try {
				JSONObject v = factionApi.getVulnerability(assessmentId, vulnId);
				if (v == null) {
					onEdt(() -> JOptionPane.showMessageDialog(this, "Could not load vulnerability.", "Faction", JOptionPane.WARNING_MESSAGE));
					return;
				}
				String description = str(v.get("description"));
				String recommendation = str(v.get("recommendation"));
				String details = str(v.get("details"));
				ImageCache.prefetch(ImageCache.referencedPaths(description, recommendation, details), factionApi::getBytes);
				onEdt(() -> {
					VulnerabilityDetailsPane pane = new VulnerabilityDetailsPane(factionApi, str(v.get("name")),
							description, recommendation, details, montoya);
					pane.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
					pane.setSize(900, 1000);
					pane.setVisible(true);
				});
			} finally {
				onEdt(() -> setCursor(Cursor.getDefaultCursor()));
			}
		}, "faction-open-vulnerability");
		t.setDaemon(true);
		t.start();
	}

	// ── Polling ─────────────────────────────────────────────────────────────────

	private void startTimer() {
		try { if (refreshTimer != null) refreshTimer.cancel(); } catch (Exception ignored) {}
		refreshTimer = new Timer();
		int period = Math.max(5, factionApi.getRefresh());
		refreshTimer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() { updateAPI(); }
		}, 0, 1000L * period);
	}

	private synchronized void updateAPI() {
		if (!factionApi.isConfigured()) return;
		final JSONArray assessments = factionApi.getAssessments();
		final JSONArray retests = factionApi.getRetests();

		Runnable apply = () -> {
			// Assessments
			for (int i = asmtModel.getRowCount() - 1; i >= 0; i--) asmtModel.removeRow(i);
			for (Object o : assessments) {
				JSONObject a = (JSONObject) o;
				Vector<Object> row = new Vector<>();
				row.add(str(a.get("appId")));
				row.add(str(a.get("name")));
				row.add(str(a.get("applicationName")));
				row.add(str(a.get("status")));
				row.add(datePart(a.get("startDate")));
				row.add(datePart(a.get("plannedEndDate")));
				row.add(str(a.get("id")));
				asmtModel.addRow(row);
			}
			// Retests
			for (int i = verModel.getRowCount() - 1; i >= 0; i--) verModel.removeRow(i);
			for (Object o : retests) {
				JSONObject r = (JSONObject) o;
				Vector<Object> row = new Vector<>();
				row.add(datePart(r.get("scheduledStartDate")));
				row.add(str(r.get("assessmentName")));
				row.add(str(r.get("vulnerabilityName")));
				row.add(str(r.get("vulnerabilitySeverity")));
				row.add(str(r.get("status")));
				row.add(str(r.get("vulnerabilityId")));
				row.add(str(r.get("assessmentId")));
				verModel.addRow(row);
			}
		};
		onEdt(apply);
		// Refresh the selected assessment's own findings; the history is reloaded on selection only.
		if (!selectedAssessmentId.isEmpty()) loadFindings(selectedAssessmentId);
	}

	private static void onEdt(Runnable r) {
		if (SwingUtilities.isEventDispatchThread()) r.run();
		else SwingUtilities.invokeLater(r);
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	/** Extracts the date portion of an ISO LocalDateTime string ("2026-07-22T…" → "2026-07-22"). */
	public static String datePart(Object iso) {
		if (iso == null) return "";
		String s = iso.toString();
		int t = s.indexOf('T');
		return t > 0 ? s.substring(0, t) : s;
	}

	private static String str(Object o) {
		return o == null ? "" : o.toString();
	}

	/** The selected assessment id, used to preselect it in the Send-to-Faction window. */
	public String getAppId() {
		return this.selectedAssessmentId;
	}

	public FactionAPI getFactionApi() {
		return this.factionApi;
	}

	@Override
	public void extensionUnloaded() {
		logging.logToOutput("Faction: stopping refresh timer");
		try { if (refreshTimer != null) refreshTimer.cancel(); } catch (Exception ignored) {}
	}
}
