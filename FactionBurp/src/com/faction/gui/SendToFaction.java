package com.faction.gui;


import javax.swing.JFrame;
import java.awt.GridBagLayout;
import javax.swing.JLabel;
import java.awt.GridBagConstraints;
import javax.swing.JComboBox;
import java.awt.Insets;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;

import org.apache.commons.lang.StringEscapeUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.faction.api.FactionAPI;
import com.faction.utils.FSUtils;
import com.sun.jersey.core.util.Base64;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext;

//import flex.messaging.util.URLEncoder;
import java.net.URLEncoder;

import javax.swing.JEditorPane;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JProgressBar;
import javax.swing.SwingWorker;
import javax.swing.TransferHandler;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import javax.imageio.ImageIO;

import javax.swing.Box;
import java.awt.Dimension;
import javax.swing.JTextField;
import javax.swing.border.LineBorder;
import java.awt.Color;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Map.Entry;
import java.awt.event.ActionEvent;
import javax.swing.DefaultComboBoxModel;
import javax.swing.border.EtchedBorder;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.JScrollPane;

import org.commonmark.node.*;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

public class SendToFaction {

	public JFrame frame;
	private JTextField vulnName;
	private FactionAPI factionApi;
	private JComboBox assessmentList;
	private JSONArray asmts;
	private JSONArray vulns;
	private JCheckBox optReq;
	private JCheckBox optCookies;
	private JCheckBox optResp;
	private JEditorPane message_1;
	private JComboBox vulnList;
	private JButton btnSave;
	private boolean isScanIssue=false;
	private boolean isNew = true;
	private Object event;
	private HashMap<String,List<AuditIssue>>scanIssues;
	private JTextField vulnSearch;
	private JComboBox defaultVulns;
	private HashMap<String, JSONObject> _defaultVulns = new HashMap<String,JSONObject>();
	private String appId;
	private JComboBox severity;
	private JComboBox sections;
	private JCheckBox useSelected;
	private LinkedHashMap<String, Integer> levels = new LinkedHashMap();
	private JScrollPane scrollPane;
	private JPanel panel_1;
	private boolean isScan;
	private JPanel customFieldsPanel;
	private JProgressBar imageSpinner;
	private LinkedHashMap<String, Component> customFieldComponents = new LinkedHashMap<>();
	
	/**
	 * Create the application.
	 */
	public SendToFaction(Object event, boolean isScan, boolean isNew, String appId, FactionAPI factionApi) {
		this.isNew = isNew;
		this.appId = appId;
		this.event = event;
		this.isScanIssue = isScan;
		this.factionApi = factionApi;

		if(isScanIssue){
			List<AuditIssue> selectedIssues = ((AuditIssueContextMenuEvent) event).selectedIssues();

			
			scanIssues = new HashMap<>();
			for(AuditIssue issue :selectedIssues){
				if(scanIssues.containsKey(issue.name()))
						scanIssues.get(issue.name()).add(issue);
				else{
					List<AuditIssue> newList = new ArrayList<>();
					newList.add(issue);
					scanIssues.put(issue.name(), newList);
				}
			}
		}
			
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		levels = factionApi.getLevelMap();
		frame = new JFrame();
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		frame.setBounds(100, 100, 1080, 777);
		//frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 130, 0, 260, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 1.0, 1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, Double.MIN_VALUE};
		frame.getContentPane().setLayout(gridBagLayout);
		
		Component rigidArea_2 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_2 = new GridBagConstraints();
		gbc_rigidArea_2.insets = new Insets(0, 0, 5, 5);
		gbc_rigidArea_2.gridx = 2;
		gbc_rigidArea_2.gridy = 0;
		frame.getContentPane().add(rigidArea_2, gbc_rigidArea_2);
		if(this.isNew){
			JLabel lblName = new JLabel("Name:");
			GridBagConstraints gbc_lblName = new GridBagConstraints();
			gbc_lblName.anchor = GridBagConstraints.EAST;
			gbc_lblName.insets = new Insets(0, 0, 5, 5);
			gbc_lblName.gridx = 1;
			gbc_lblName.gridy = 1;
			frame.getContentPane().add(lblName, gbc_lblName);
			
			vulnName = new JTextField();
			if(scanIssues != null){
				if(scanIssues.size() == 1)
					vulnName.setText(scanIssues.keySet().iterator().next());
				else
					vulnName.setText("Multiple Issues Selected");
				
			}
			GridBagConstraints gbc_vulnName = new GridBagConstraints();
			gbc_vulnName.fill = GridBagConstraints.HORIZONTAL;
			gbc_vulnName.insets = new Insets(0, 0, 5, 5);
			gbc_vulnName.gridx = 2;
			gbc_vulnName.gridy = 1;
			frame.getContentPane().add(vulnName, gbc_vulnName);
			vulnName.setColumns(10);
		}
		
		JLabel lblAssessment = new JLabel("Assessment:");
		GridBagConstraints gbc_lblAssessment = new GridBagConstraints();
		gbc_lblAssessment.fill = GridBagConstraints.HORIZONTAL;
		gbc_lblAssessment.insets = new Insets(0, 0, 5, 5);
		gbc_lblAssessment.gridx = 1;
		gbc_lblAssessment.gridy = 2;
		frame.getContentPane().add(lblAssessment, gbc_lblAssessment);
		
		assessmentList = new JComboBox();
		assessmentList.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				int index = assessmentList.getSelectedIndex();
				if(index < 0 || asmts == null || index >= asmts.size())
					return;
				JSONObject obj = (JSONObject)asmts.get(index);
				loadCustomFields("" + obj.get("Id"));
				if(!isNew){
					vulns = factionApi.executeGet(FactionAPI.GETVULNS + obj.get("Id"));
					vulnList.removeAllItems();
					for(int i=0; i< vulns.size(); i++){
						JSONObject vuln = (JSONObject)vulns.get(i);
						vulnList.addItem("" + vuln.get("Name"));
					}
					if(vulns.size() == 0){
						btnSave.setEnabled(false);

					}else{
						btnSave.setEnabled(true);
					}


				}
			}
		});
		
		GridBagConstraints gbc_assessmentList = new GridBagConstraints();
		gbc_assessmentList.insets = new Insets(0, 0, 5, 5);
		gbc_assessmentList.fill = GridBagConstraints.HORIZONTAL;
		gbc_assessmentList.gridx = 2;
		gbc_assessmentList.gridy = 2;
		frame.getContentPane().add(assessmentList, gbc_assessmentList);
		
		if(!this.isNew){
			JLabel lblVulnerability = new JLabel("Vulnerability:");
			GridBagConstraints gbc_lblVulnerability = new GridBagConstraints();
			gbc_lblVulnerability.anchor = GridBagConstraints.EAST;
			gbc_lblVulnerability.insets = new Insets(0, 0, 5, 5);
			gbc_lblVulnerability.gridx = 1;
			gbc_lblVulnerability.gridy = 3;
			frame.getContentPane().add(lblVulnerability, gbc_lblVulnerability);
			
			vulnList = new JComboBox();
			vulnList.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent arg0) {
					int index = vulnList.getSelectedIndex();
					if(index < 0 || vulns == null || index >= vulns.size())
						return;
					JSONObject vuln = (JSONObject)vulns.get(index);
					prefillCustomFields("" + vuln.get("Id"));
				}
			});
			GridBagConstraints gbc_vulnList = new GridBagConstraints();
			gbc_vulnList.insets = new Insets(0, 0, 5, 5);
			gbc_vulnList.fill = GridBagConstraints.HORIZONTAL;
			gbc_vulnList.gridx = 2;
			gbc_vulnList.gridy = 3;
			frame.getContentPane().add(vulnList, gbc_vulnList);
		}
		
		JPanel searchPanel = new JPanel();
		searchPanel.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Search Default Vulns", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(59, 59, 59)));
		GridBagConstraints gbc_searchPanel = new GridBagConstraints();
		gbc_searchPanel.gridwidth = 2;
		gbc_searchPanel.insets = new Insets(0, 0, 5, 5);
		gbc_searchPanel.fill = GridBagConstraints.BOTH;
		gbc_searchPanel.gridx = 1;
		gbc_searchPanel.gridy = 4;
		frame.getContentPane().add(searchPanel, gbc_searchPanel);
		GridBagLayout gbl_searchPanel = new GridBagLayout();
		gbl_searchPanel.columnWidths = new int[]{0, 0, 0, 0};
		gbl_searchPanel.rowHeights = new int[]{0, 0, 0};
		gbl_searchPanel.columnWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_searchPanel.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		searchPanel.setLayout(gbl_searchPanel);
		
		if(!this.isNew || this.isScanIssue){
			searchPanel.setVisible(false);
		}
		
		JLabel lblSearch = new JLabel("Search");
		GridBagConstraints gbc_lblSearch = new GridBagConstraints();
		gbc_lblSearch.insets = new Insets(0, 0, 5, 5);
		gbc_lblSearch.anchor = GridBagConstraints.EAST;
		gbc_lblSearch.gridx = 1;
		gbc_lblSearch.gridy = 0;
		searchPanel.add(lblSearch, gbc_lblSearch);
		
		vulnSearch = new JTextField();
		vulnSearch.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent arg0) {
				if(vulnSearch.getText().length() >= 2 ){
					JSONArray jarray = factionApi.executeGet(FactionAPI.SEARCH_DEFAULT_VULN + vulnSearch.getText());
					if(defaultVulns.getItemCount() > 0){
						defaultVulns.removeAllItems();
						_defaultVulns.clear();
					}
					for(int i=0; i< jarray.size();i++){
						JSONObject obj = (JSONObject)jarray.get(i);
						defaultVulns.addItem(""+obj.get("Name"));
						_defaultVulns.put(""+obj.get("Name"), obj);
						int sev = ((Long)obj.get("Overall")).intValue();
						String sevStr = "";
						for(String key : levels.keySet()){
							if(((int)levels.get(key)) == sev){
								sevStr = key;
								break;
							}
						}
						for(int j =0; j<severity.getItemCount(); j++){
							if(severity.getItemAt(j).equals(sevStr)){
								severity.setSelectedIndex(j);
								break;
							}
								
						}
						
						if(vulnName.getText().equals(""))
							vulnName.setText(""+obj.get("Name"));
					}
				}else{
					if(defaultVulns.getItemCount() > 0){
						defaultVulns.removeAllItems();
						_defaultVulns.clear();
					}
				}
				
			}
		});
		GridBagConstraints gbc_vulnSearch = new GridBagConstraints();
		gbc_vulnSearch.insets = new Insets(0, 0, 5, 0);
		gbc_vulnSearch.fill = GridBagConstraints.HORIZONTAL;
		gbc_vulnSearch.gridx = 2;
		gbc_vulnSearch.gridy = 0;
		searchPanel.add(vulnSearch, gbc_vulnSearch);
		vulnSearch.setColumns(10);
		
		defaultVulns = new JComboBox();
		defaultVulns.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String vuln = ""+defaultVulns.getSelectedItem();
				vulnName.setText(vuln);
				JSONObject obj = _defaultVulns.get(vuln);
				if(obj != null){
					int sev = ((Long)obj.get("Overall")).intValue();
					String sevStr = "";
					for(String key : levels.keySet()){
						if(((int)levels.get(key)) == sev){
							sevStr = key;
							break;
						}
					}
					for(int j =0; j<severity.getItemCount(); j++){
						if(severity.getItemAt(j).equals(sevStr)){
							severity.setSelectedIndex(j);
							break;
						}
							
					}
				}
					//severity.setSelectedIndex(((Long)obj.get("Overall")).intValue());
				
			}
		});
		GridBagConstraints gbc_defaultVulns = new GridBagConstraints();
		gbc_defaultVulns.fill = GridBagConstraints.HORIZONTAL;
		gbc_defaultVulns.gridx = 2;
		gbc_defaultVulns.gridy = 1;
		searchPanel.add(defaultVulns, gbc_defaultVulns);
		
		Component rigidArea = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea = new GridBagConstraints();
		gbc_rigidArea.insets = new Insets(0, 0, 5, 5);
		gbc_rigidArea.gridx = 0;
		gbc_rigidArea.gridy = 5;
		frame.getContentPane().add(rigidArea, gbc_rigidArea);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new LineBorder(new Color(192, 192, 192)), "Options", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(59, 59, 59)));
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.insets = new Insets(0, 0, 5, 5);
		gbc_panel.gridwidth = 2;
		gbc_panel.fill = GridBagConstraints.BOTH;
		gbc_panel.gridx = 1;
		gbc_panel.gridy = 5;
		frame.getContentPane().add(panel, gbc_panel);
		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{72, 69, 96, 80, 96, 101, 116, 0};
		gbl_panel.rowHeights = new int[]{26, 0, 0};
		gbl_panel.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
		panel.setLayout(gbl_panel);
		
		optReq = new JCheckBox("Request");
		optReq.setToolTipText("Sent the Request to Faction. If the Request is empty then only the Vulnerability will be created and exploit steps will not be added.");
		optReq.setSelected(true);
		GridBagConstraints gbc_optReq = new GridBagConstraints();
		gbc_optReq.anchor = GridBagConstraints.WEST;
		gbc_optReq.insets = new Insets(0, 0, 5, 5);
		gbc_optReq.gridx = 1;
		gbc_optReq.gridy = 0;
		panel.add(optReq, gbc_optReq);
		
		optCookies = new JCheckBox("Snip Cookies");
		optCookies.setToolTipText("This will replace the cookies in the request and response with \"[...snip...]\"");
		GridBagConstraints gbc_optCookies = new GridBagConstraints();
		gbc_optCookies.anchor = GridBagConstraints.WEST;
		gbc_optCookies.insets = new Insets(0, 0, 5, 5);
		gbc_optCookies.gridx = 2;
		gbc_optCookies.gridy = 0;
		panel.add(optCookies, gbc_optCookies);
		
		optResp = new JCheckBox("Response");
		optResp.setToolTipText("Sent the Response to Faction. If the Response is empty then only the Vulnerability will be created and exploit steps will not be added.");
		optResp.setSelected(true);
		GridBagConstraints gbc_optResp = new GridBagConstraints();
		gbc_optResp.anchor = GridBagConstraints.WEST;
		gbc_optResp.insets = new Insets(0, 0, 0, 5);
		gbc_optResp.gridx = 1;
		gbc_optResp.gridy = 1;
		panel.add(optResp, gbc_optResp);
		
		useSelected = new JCheckBox("Extract Selection");
		useSelected.setToolTipText("This will include only the selected text to be sent to Faction. If no text is selected then the entire request will be sent to Faction. This will only extract text from the area that the click originated from(i.e. if you have text selected in the Response but right clicked in the request then the full request and response will be sent to Faction.\r\n\r\nThis setting has no effect if multiple issues are selected or scan issues are selected. ");
		useSelected.setSelected(true);
		GridBagConstraints gbc_useSelected = new GridBagConstraints();
		gbc_useSelected.anchor = GridBagConstraints.WEST;
		gbc_useSelected.insets = new Insets(0, 0, 0, 5);
		gbc_useSelected.gridx = 2;
		gbc_useSelected.gridy = 1;
		panel.add(useSelected, gbc_useSelected);
		
		// Only show the Section control if the report-sections endpoint exists
		// and returns sections (older API versions don't have this endpoint).
		JSONArray sectionList = factionApi.getReportSections();
		if(sectionList != null && sectionList.size() > 0){
			JLabel lblSection = new JLabel("Section:");
			GridBagConstraints gbc_lblSection = new GridBagConstraints();
			gbc_lblSection.anchor = GridBagConstraints.WEST;
			gbc_lblSection.insets = new Insets(0, 0, 5, 5);
			gbc_lblSection.gridx = 3;
			gbc_lblSection.gridy = 0;
			panel.add(lblSection, gbc_lblSection);

			sections = new JComboBox();
			sections.setToolTipText("Set the report Section for this vulnerability.");
			for(Object s : sectionList){
				sections.addItem("" + s);
			}
			GridBagConstraints gbc_sections = new GridBagConstraints();
			gbc_sections.insets = new Insets(0, 0, 5, 5);
			gbc_sections.fill = GridBagConstraints.HORIZONTAL;
			gbc_sections.gridwidth = 3;
			gbc_sections.gridx = 4;
			gbc_sections.gridy = 0;
			panel.add(sections, gbc_sections);
		}

		severity = new JComboBox();
		severity.setToolTipText("Set the Overall Severity of the issue.");
		String [] severityStrings = factionApi.getSeverityStrings();
		FSUtils.setSeverityComboBoxDefaults(factionApi, severity, FactionAPI.BURP_SEV_HIGH, severityStrings, (updatedSeverityString) ->{});

		GridBagConstraints gbc_severity = new GridBagConstraints();
		gbc_severity.insets = new Insets(0, 0, 0, 5);
		gbc_severity.anchor = GridBagConstraints.NORTHWEST;
		gbc_severity.gridx = 3;
		gbc_severity.gridy = 1;
		panel.add(severity, gbc_severity);
		
		Component rigidArea_1 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_1 = new GridBagConstraints();
		gbc_rigidArea_1.insets = new Insets(0, 0, 5, 0);
		gbc_rigidArea_1.gridx = 3;
		gbc_rigidArea_1.gridy = 5;
		frame.getContentPane().add(rigidArea_1, gbc_rigidArea_1);
		
		panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Exploit Steps (Supports Markdown)", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		GridBagConstraints gbc_panel_1 = new GridBagConstraints();
		gbc_panel_1.fill = GridBagConstraints.BOTH;
		gbc_panel_1.gridwidth = 2;
		gbc_panel_1.insets = new Insets(0, 0, 5, 5);
		gbc_panel_1.gridx = 1;
		gbc_panel_1.gridy = 6;
		frame.getContentPane().add(panel_1, gbc_panel_1);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{130, 0, 0};
		gbl_panel_1.rowHeights = new int[]{0, 0, 0};
		gbl_panel_1.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{0.0, 1.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);

		JButton btnInsertImage = new JButton("Insert Image");
		btnInsertImage.setToolTipText("Upload an image to the selected assessment and insert a markdown link at the cursor.");
		btnInsertImage.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String aid = selectedAssessmentId();
				if(aid == null)
					return;
				uploadAndInsertImage(aid);
			}
		});
		GridBagConstraints gbc_btnInsertImage = new GridBagConstraints();
		gbc_btnInsertImage.anchor = GridBagConstraints.WEST;
		gbc_btnInsertImage.insets = new Insets(0, 0, 5, 5);
		gbc_btnInsertImage.gridx = 0;
		gbc_btnInsertImage.gridy = 0;
		panel_1.add(btnInsertImage, gbc_btnInsertImage);

		// Hint that images can also be pasted directly, plus an upload spinner
		// that is shown while an image is being uploaded to the API.
		JPanel imageHintPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
		JLabel pasteHint = new JLabel("or paste an image directly into the form to add it");
		pasteHint.setFont(pasteHint.getFont().deriveFont(Font.ITALIC));
		pasteHint.setForeground(Color.GRAY);
		imageHintPanel.add(pasteHint);
		imageSpinner = new JProgressBar();
		imageSpinner.setIndeterminate(true);
		imageSpinner.setStringPainted(true);
		imageSpinner.setString("Uploading…");
		imageSpinner.setPreferredSize(new Dimension(110, 18));
		imageSpinner.setVisible(false);
		imageHintPanel.add(imageSpinner);
		GridBagConstraints gbc_imageHintPanel = new GridBagConstraints();
		gbc_imageHintPanel.anchor = GridBagConstraints.WEST;
		gbc_imageHintPanel.insets = new Insets(0, 0, 5, 5);
		gbc_imageHintPanel.gridx = 1;
		gbc_imageHintPanel.gridy = 0;
		panel_1.add(imageHintPanel, gbc_imageHintPanel);

		scrollPane = new JScrollPane();
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridwidth = 2;
		gbc_scrollPane.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 1;
		panel_1.add(scrollPane, gbc_scrollPane);
		
		message_1 = new JEditorPane();
		scrollPane.setViewportView(message_1);
		message_1.setText("Enter Exploit Steps or Additional Informaiton here");
		message_1.setContentType("text/plain");
		// Intercept image pastes: upload to the API and insert a markdown link in place.
		message_1.setTransferHandler(new ImagePasteHandler(message_1.getTransferHandler()));

		customFieldsPanel = new JPanel();
		customFieldsPanel.setLayout(new GridBagLayout());
		JScrollPane customFieldsScroll = new JScrollPane(customFieldsPanel);
		customFieldsScroll.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Custom Fields", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		customFieldsScroll.getVerticalScrollBar().setUnitIncrement(12);
		GridBagConstraints gbc_customFieldsScroll = new GridBagConstraints();
		gbc_customFieldsScroll.fill = GridBagConstraints.BOTH;
		gbc_customFieldsScroll.insets = new Insets(0, 0, 5, 5);
		gbc_customFieldsScroll.gridx = 3;
		gbc_customFieldsScroll.gridy = 6;
		frame.getContentPane().add(customFieldsScroll, gbc_customFieldsScroll);

		btnSave = new JButton("Save");
		/*
		 * This is the action listener that saves a new vuln
		 * to FACTION
		 */
		btnSave.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String msg = message_1.getText();
				
				if(isNew){
					if(isScanIssue){ // we are using scan issues
						int index = assessmentList.getSelectedIndex();
						JSONObject obj = (JSONObject)asmts.get(index);
						Iterator entries = scanIssues.keySet().iterator();
						while(entries.hasNext()){
							String scanIssueKey = (String) entries.next();
							List<AuditIssue> issues = scanIssues.get(scanIssueKey);
							AuditIssue baseIssue = issues.get(0);
							String b64Description = new String(Base64.encode(baseIssue.definition().background()));
							String b64Recommendation = new String(Base64.encode(""+baseIssue.definition().remediation()));
							LinkedHashMap<String, String> supportingDetails = new LinkedHashMap();
							String details = "<b><u>Affected URLs:</u></b>\n<ul>\n";
							for(AuditIssue issue : issues){
								details += "<li>" + issue.baseUrl() + "</li>\n";
								if(issue.detail() != null){
									String hash = FSUtils.hashText(issue.detail());
									supportingDetails.put(hash, issue.detail());
								}
							}
							details += "</ul>\n";
							String supportingDetailText = "";
							for(Entry<String,String> entry : supportingDetails.entrySet()){
								supportingDetailText += entry.getValue() + "\n";
							}
							details += createScanMessage(baseIssue);
							details = supportingDetailText + details;
							String b64Details = new String(Base64.encode(details));
							try{
								String postData = "name="+ URLEncoder.encode(baseIssue.name(), "UTF-8") 
								+ "&feed=false"
								+ "&details=" +URLEncoder.encode(b64Details, "UTF-8")
								+ "&description=" + URLEncoder.encode(b64Description, "UTF-8")
								+ "&recommendation="+ URLEncoder.encode(b64Recommendation, "UTF-8")
								+ "&severity=" + factionApi.getSevMapping(baseIssue.severity().name());
								String cf = customFieldsValue();
								if(!cf.isEmpty())
									postData += "&customFields=" + cf;
								String section = sectionValue();
								if(!section.isEmpty())
									postData += "&section=" + section;
								factionApi.executePost(FactionAPI.ADDVULN + obj.get("Id"), postData);
							} catch (UnsupportedEncodingException ex){
								System.out.println(ex.getMessage());
							}
							
						}
					}else{ // adding a new vuln
						String b64 = new String(Base64.encode(createMessage((ContextMenuEvent)event)));
						String name = vulnName.getText();
						int index = assessmentList.getSelectedIndex();
						JSONObject obj = (JSONObject)asmts.get(index);
						try{
							String postData = "name=" + URLEncoder.encode(name, "UTF-8")
							+ "&feed=false&details=" + URLEncoder.encode(b64, "UTF-8");
							postData+="&severity=" + levels.get(""+severity.getSelectedItem());
							String cf = customFieldsValue();
							if(!cf.isEmpty())
								postData += "&customFields=" + cf;
							String section = sectionValue();
							if(!section.isEmpty())
								postData += "&section=" + section;
							if(_defaultVulns.size() > 0){
								JSONObject vobj = _defaultVulns.get(defaultVulns.getSelectedItem());
								factionApi.executePost(FactionAPI.ADDDEFAULTVULN + obj.get("Id") + "/" + vobj.get("Id"), postData);
							}else{
								factionApi.executePost(FactionAPI.ADDVULN + obj.get("Id"), postData);
							}
						} catch (UnsupportedEncodingException ex){
							System.out.println(ex.getMessage());
						}

						
					}
				}else{  // adding an existing vuln
					String b64 = new String(Base64.encode(createMessage((ContextMenuEvent)event)));
					int aindex = assessmentList.getSelectedIndex();
					int vindex  = vulnList.getSelectedIndex();
					JSONObject aObj = (JSONObject)asmts.get(aindex);
					JSONObject vObj = (JSONObject)vulns.get(vindex);
					String postData = "feed=false&details=" +URLEncoder.encode(b64);
					postData+="&severity=" + levels.get(""+severity.getSelectedItem());
					factionApi.executePost(FactionAPI.ADDVULN + aObj.get("Id") + "/" + vObj.get("Id"), postData);

					String cf = customFieldsValue();
					if(!cf.isEmpty())
						factionApi.executePost(FactionAPI.GETVULN + vObj.get("Id") + "/customfields", "customFields=" + cf);

					String section = sectionValue();
					if(!section.isEmpty())
						factionApi.executePost(FactionAPI.GETVULN + vObj.get("Id"), "section=" + section);

				}
				
				frame.dispose();
			}
		});
		GridBagConstraints gbc_btnSave = new GridBagConstraints();
		gbc_btnSave.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnSave.insets = new Insets(0, 0, 5, 5);
		gbc_btnSave.gridx = 1;
		gbc_btnSave.gridy = 7;
		frame.getContentPane().add(btnSave, gbc_btnSave);
		
		Component rigidArea_3 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_3 = new GridBagConstraints();
		gbc_rigidArea_3.insets = new Insets(0, 0, 0, 5);
		gbc_rigidArea_3.gridx = 2;
		gbc_rigidArea_3.gridy = 8;
		frame.getContentPane().add(rigidArea_3, gbc_rigidArea_3);
		
		asmts = factionApi.executeGet("/assessments/queue");
		for(int i=0; i< asmts.size(); i++){
			JSONObject obj = (JSONObject)asmts.get(i);
			assessmentList.addItem(obj.get("AppId") + " " + obj.get("Name"));
			if(this.appId != null && (""+obj.get("AppId")).equals(this.appId) )
				assessmentList.setSelectedIndex(i);
		}
		
		
	}
	
	private String createScanMessage(AuditIssue issue){
		String message = this.getMessage().getText();
		
		message = message.replaceAll("\r\n", "<br/>").replaceAll("\n", "<br/>");
		message +="<br/>";
		if(issue.requestResponses() != null && issue.requestResponses().size() > 0){
			HttpRequestResponse reqres = issue.requestResponses().get(0);
				
			if(this.optReq.isSelected() && reqres.request() != null){
				String req = reqres.request().toString();
				message += "<b>Request: </b>";
				message += "<pre class='code'>";
				if(this.optCookies.isSelected()){
					req = req.replaceAll("Cookie: .*\n", "Cookie: [ ...snip... ]\n");
				}
				String data = StringEscapeUtils.escapeHtml(req);
				data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				message += data;
				message += "</pre>";
			}
			if(this.optResp.isSelected() && reqres.hasResponse()){
				String resp = reqres.response().toString();
				message += "<b>Response: </b>";
				message += "<pre class='code'>";
				if(this.optCookies.isSelected()){
					resp = resp.replaceAll("Set-Cookie: .*\n", "Set-Cookie: [ ...snip... ]\n");
				}
				String data = StringEscapeUtils.escapeHtml(resp);
				data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				message += data;
				message += "</pre>";
			}
		}
		return message;
		
		
	}
	private String createMessage(ContextMenuEvent event){
		String message = this.getMessage().getText();
		Parser parser = Parser.builder().build();
		Node document = parser.parse(message);
		HtmlRenderer renderer = HtmlRenderer.builder().build();
		message = renderer.render(document);
		message = message.replaceAll("<code>", "<pre>").replaceAll("</code>", "</pre>");
		message = message.replaceAll("</p>", "<br/>");
		message +="<br>";
		StringBuilder _message = new StringBuilder(message);
		Optional<MessageEditorHttpRequestResponse>  req = event.messageEditorRequestResponse();
		req.ifPresent( r -> {
			StringBuilder request = new StringBuilder("");
			if(this.optReq.isSelected()){
				request.append(r.requestResponse().request().toString());
			}
			StringBuilder response = new StringBuilder("");
			if( this.optResp.isSelected() && r.requestResponse().hasResponse()){
				response.append(r.requestResponse().response().toString());
			}
			r.selectionOffsets().ifPresent( range ->{
				int start = range.startIndexInclusive();
				int end = range.endIndexExclusive();
				if(r.selectionContext() == SelectionContext.REQUEST && this.optReq.isSelected()){
					request.setLength(0);
					request.append(new String(Arrays.copyOfRange(r.requestResponse().request().toByteArray().getBytes(),start,end)));
					if(start != 0){
						request.insert(0,"[ ...snip... ]\r\n");
						request.append("\r\n[ ...snip... ]");
					}else{
						request.append("\r\n[ ...snip... ]");
					}
				}else if (this.optReq.isSelected()){
					response.setLength(0);
					response.append(new String(Arrays.copyOfRange(r.requestResponse().response().toByteArray().getBytes(),start,end)));
					if(start != 0){
						response.insert(0,"[ ...snip... ]\r\n");
						response.append("\r\n[ ...snip... ]");
					}else{
						response.append("\r\n[ ...snip... ]");
					}
				}


			});
			if(this.optCookies.isSelected()){
				String tmpRequest = request.toString();
				tmpRequest = tmpRequest.replaceAll("Cookie: .*", "Cookie: [ ...snip... ]");
				request.setLength(0);
				request.append(tmpRequest);
				String tmpResponse = response.toString();
				tmpResponse = tmpResponse.replaceAll("Set-Cookie: .*", "Set-Cookie: [ ...snip... ]");
				response.setLength(0);
				response.append(tmpResponse);
			}
				
			String data = StringEscapeUtils.escapeHtml(request.toString());
			data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
			if(this.optReq.isSelected()){
				_message.append("<b>Request: </b>");
				_message.append("<pre class='code'><code>");
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				_message.append(data);
				_message.append("</code></pre>");
			}
			if(this.optResp.isSelected()){
				data = StringEscapeUtils.escapeHtml(response.toString());
				data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
				_message.append("<b>Response: </b>");
				_message.append("<pre class='code'><code>");
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				_message.append(data);
				_message.append("</code></pre>");
			}
		});
		return _message.toString();
	}
	

	/**
	 * Prompts the user to choose an image file, uploads it to the assessment as
	 * a base64 data URI, and inserts the returned markdown link into the exploit
	 * steps editor at the current cursor position.
	 */
	private void uploadAndInsertImage(String aid){
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Select an Image to Upload");
		chooser.setFileFilter(new FileNameExtensionFilter("Images (png, jpg, jpeg, gif, bmp, webp)", "png", "jpg", "jpeg", "gif", "bmp", "webp"));
		if(chooser.showOpenDialog(frame) != JFileChooser.APPROVE_OPTION)
			return;
		File file = chooser.getSelectedFile();
		try {
			byte[] bytes = Files.readAllBytes(file.toPath());
			String mime = Files.probeContentType(file.toPath());
			if(mime == null || !mime.startsWith("image"))
				mime = mimeFromName(file.getName());
			uploadImageBytesAndInsert(bytes, mime, aid);
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
			JOptionPane.showMessageDialog(frame, "Error uploading image: " + ex.getMessage(), "Upload Error", JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Uploads raw image bytes to the assessment's image endpoint and inserts the
	 * returned markdown link at the caret. Shared by the "Insert Image" button
	 * (file chooser) and the clipboard paste handler.
	 *
	 * The network call runs on a background worker so the UI stays responsive and
	 * the upload spinner can animate; the caret insert happens back on the EDT.
	 */
	private void uploadImageBytesAndInsert(final byte[] bytes, final String mime, final String aid) {
		setImageUploading(true);
		SwingWorker<String, Void> worker = new SwingWorker<String, Void>() {
			protected String doInBackground() throws Exception {
				String dataUri = "data:" + mime + ";base64," + new String(Base64.encode(bytes));
				String postData = "encodedImage=" + URLEncoder.encode(dataUri, "UTF-8");
				JSONObject resp = factionApi.executePostObject(FactionAPI.IMAGE + aid, postData);
				return extractMarkdownLink(resp);
			}
			protected void done() {
				setImageUploading(false);
				try {
					String markdown = get();
					if(markdown == null || markdown.isEmpty()){
						JOptionPane.showMessageDialog(frame, "Image upload failed or no link was returned.", "Upload Failed", JOptionPane.ERROR_MESSAGE);
						return;
					}
					int pos = message_1.getCaretPosition();
					message_1.getDocument().insertString(pos, markdown, null);
					message_1.setCaretPosition(pos + markdown.length());
					message_1.requestFocusInWindow();
				} catch (Exception ex) {
					System.out.println(ex.getMessage());
					JOptionPane.showMessageDialog(frame, "Error uploading image: " + ex.getMessage(), "Upload Error", JOptionPane.ERROR_MESSAGE);
				}
			}
		};
		worker.execute();
	}

	/** Shows or hides the image upload spinner. Must be called on the EDT. */
	private void setImageUploading(boolean uploading){
		if(imageSpinner != null)
			imageSpinner.setVisible(uploading);
	}

	/** Returns the Id of the currently selected assessment, or null if none. */
	private String selectedAssessmentId(){
		int index = assessmentList.getSelectedIndex();
		if(index < 0 || asmts == null || index >= asmts.size())
			return null;
		JSONObject obj = (JSONObject)asmts.get(index);
		return "" + obj.get("Id");
	}

	/**
	 * TransferHandler for the markdown editor that intercepts pastes containing an
	 * image. Image pastes are uploaded to the API and replaced with a markdown
	 * link in place; all other pastes fall through to the default text behavior.
	 */
	private class ImagePasteHandler extends TransferHandler {
		private final TransferHandler delegate;
		ImagePasteHandler(TransferHandler delegate){
			this.delegate = delegate;
		}
		@Override
		public boolean canImport(TransferSupport support){
			if(support.isDataFlavorSupported(DataFlavor.imageFlavor))
				return true;
			return delegate != null && delegate.canImport(support);
		}
		@Override
		public boolean importData(TransferSupport support){
			if(support.isDataFlavorSupported(DataFlavor.imageFlavor)){
				String aid = selectedAssessmentId();
				if(aid == null){
					JOptionPane.showMessageDialog(frame, "Select an assessment before pasting an image.", "No Assessment", JOptionPane.WARNING_MESSAGE);
					return true;
				}
				try {
					Image img = (Image)support.getTransferable().getTransferData(DataFlavor.imageFlavor);
					BufferedImage buffered = toBufferedImage(img);
					ByteArrayOutputStream baos = new ByteArrayOutputStream();
					ImageIO.write(buffered, "png", baos);
					uploadImageBytesAndInsert(baos.toByteArray(), "image/png", aid);
				} catch (Exception ex) {
					System.out.println(ex.getMessage());
					JOptionPane.showMessageDialog(frame, "Error uploading pasted image: " + ex.getMessage(), "Upload Error", JOptionPane.ERROR_MESSAGE);
				}
				return true;
			}
			return delegate != null && delegate.importData(support);
		}
		@Override
		public int getSourceActions(JComponent c){
			return delegate != null ? delegate.getSourceActions(c) : NONE;
		}
		@Override
		protected Transferable createTransferable(JComponent c){
			return delegate != null ? null : super.createTransferable(c);
		}
	}

	/** Converts an arbitrary AWT Image into a BufferedImage suitable for ImageIO. */
	private static BufferedImage toBufferedImage(Image img){
		if(img instanceof BufferedImage)
			return (BufferedImage)img;
		int w = Math.max(1, img.getWidth(null));
		int h = Math.max(1, img.getHeight(null));
		BufferedImage buffered = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = buffered.createGraphics();
		g.drawImage(img, 0, 0, null);
		g.dispose();
		return buffered;
	}

	private String mimeFromName(String name){
		String n = name.toLowerCase();
		if(n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
		if(n.endsWith(".gif")) return "image/gif";
		if(n.endsWith(".bmp")) return "image/bmp";
		if(n.endsWith(".webp")) return "image/webp";
		if(n.endsWith(".svg")) return "image/svg+xml";
		return "image/png";
	}

	/**
	 * The image upload endpoint returns the GUID and a markdown link. The exact
	 * key isn't pinned in the API docs, so try the likely names and fall back to
	 * any value that looks like a markdown link.
	 */
	private String extractMarkdownLink(JSONObject resp){
		if(resp == null)
			return null;
		String[] keys = {"markdown", "Markdown", "markdownLink", "MarkdownLink", "link", "Link", "url", "Url"};
		for(String k : keys){
			Object v = resp.get(k);
			if(v != null && v.toString().contains("]("))
				return v.toString();
		}
		for(Object v : resp.values()){
			if(v != null && v.toString().contains("]("))
				return v.toString();
		}
		return null;
	}

	/**
	 * Pulls the allowed Vulnerability custom field definitions for the given
	 * assessment and rebuilds the Custom Fields panel with the appropriate
	 * widget for each field (text box, dropdown, or checkbox).
	 */
	private void loadCustomFields(String aid){
		customFieldComponents.clear();
		customFieldsPanel.removeAll();
		JSONObject resp = factionApi.getCustomFields(aid);
		JSONArray fields = (JSONArray) resp.get("vulnerabilityFields");
		int row = 0;
		if(fields != null){
			for(Object o : fields){
				JSONObject f = (JSONObject)o;
				String key = "" + f.get("Key");
				String fieldType = f.get("FieldType") == null ? "String" : "" + f.get("FieldType");
				String defaultValue = f.get("DefaultValue") == null ? "" : "" + f.get("DefaultValue");
				boolean readonly = Boolean.TRUE.equals(f.get("Readonly"));

				// Boolean and Rich Text fields are intentionally skipped.
				if(fieldType.equalsIgnoreCase("Boolean") || fieldType.equalsIgnoreCase("Rich Text"))
					continue;

				JLabel label = new JLabel(key + ":");
				GridBagConstraints lg = new GridBagConstraints();
				lg.anchor = GridBagConstraints.WEST;
				lg.insets = new Insets(2, 2, 2, 5);
				lg.gridx = 0;
				lg.gridy = row;
				customFieldsPanel.add(label, lg);

				Component comp = createCustomFieldComponent(fieldType, defaultValue, readonly);
				GridBagConstraints cg = new GridBagConstraints();
				cg.fill = GridBagConstraints.HORIZONTAL;
				cg.weightx = 1.0;
				cg.insets = new Insets(2, 0, 2, 2);
				cg.gridx = 1;
				cg.gridy = row;
				customFieldsPanel.add(comp, cg);

				// The backend keys custom fields by the display Key (e.g.
				// "Affected URL"), not the Variable, so map widgets by Key.
				customFieldComponents.put(key, comp);
				row++;
			}
		}
		// filler row to keep fields anchored to the top
		GridBagConstraints filler = new GridBagConstraints();
		filler.gridx = 0;
		filler.gridy = row;
		filler.gridwidth = 2;
		filler.weighty = 1.0;
		filler.fill = GridBagConstraints.BOTH;
		customFieldsPanel.add(Box.createGlue(), filler);

		customFieldsPanel.revalidate();
		customFieldsPanel.repaint();
	}

	/**
	 * Builds the input widget for a custom field based on its FieldType.
	 * "List"  -> dropdown (options are comma separated in DefaultValue)
	 * "Boolean" -> checkbox
	 * anything else (e.g. "String") -> text field
	 */
	private Component createCustomFieldComponent(String fieldType, String defaultValue, boolean readonly){
		Component comp;
		if(fieldType.equalsIgnoreCase("Boolean")){
			JCheckBox cb = new JCheckBox();
			cb.setSelected(defaultValue.equalsIgnoreCase("true"));
			cb.setEnabled(!readonly);
			comp = cb;
		}else if(fieldType.equalsIgnoreCase("List")){
			JComboBox combo = new JComboBox();
			combo.addItem("");
			for(String opt : defaultValue.split(",")){
				if(!opt.trim().isEmpty())
					combo.addItem(opt.trim());
			}
			combo.setEnabled(!readonly);
			comp = combo;
		}else{
			JTextField tf = new JTextField();
			tf.setText(defaultValue);
			tf.setColumns(10);
			tf.setEnabled(!readonly);
			comp = tf;
		}
		return comp;
	}

	/**
	 * Loads an existing vulnerability's saved Section and custom field values
	 * into the form (used when editing an existing vulnerability).
	 */
	private void prefillCustomFields(String vid){
		JSONObject vuln = factionApi.executeGetObject(FactionAPI.GETVULN + vid);

		// Select the vulnerability's current report Section, if any.
		if(sections != null && vuln.get("Section") != null){
			String section = "" + vuln.get("Section");
			for(int i = 0; i < sections.getItemCount(); i++){
				if(section.equals("" + sections.getItemAt(i))){
					sections.setSelectedIndex(i);
					break;
				}
			}
		}

		if(customFieldComponents.isEmpty())
			return;
		JSONArray cfs = (JSONArray) vuln.get("CustomFields");
		if(cfs == null)
			return;
		for(Object o : cfs){
			JSONObject cf = (JSONObject)o;
			String key = "" + cf.get("Key");
			String value = cf.get("Value") == null ? "" : "" + cf.get("Value");
			Component comp = customFieldComponents.get(key);
			if(comp == null)
				continue;
			setComponentValue(comp, value);
		}
	}

	private void setComponentValue(Component comp, String value){
		if(comp instanceof JCheckBox){
			((JCheckBox)comp).setSelected(value.equalsIgnoreCase("true"));
		}else if(comp instanceof JComboBox){
			JComboBox combo = (JComboBox)comp;
			boolean found = false;
			for(int i = 0; i < combo.getItemCount(); i++){
				if(value.equals("" + combo.getItemAt(i))){
					found = true;
					break;
				}
			}
			if(!found && !value.isEmpty())
				combo.addItem(value);
			combo.setSelectedItem(value);
		}else if(comp instanceof JTextField){
			((JTextField)comp).setText(value);
		}
	}

	/**
	 * Serializes the current custom field widget values to a URL-encoded JSON
	 * object keyed by each field's display Key. Returns "" when there are no
	 * custom fields so callers can skip the parameter entirely.
	 */
	private String customFieldsValue(){
		if(customFieldComponents.isEmpty())
			return "";
		JSONObject obj = new JSONObject();
		for(Entry<String, Component> e : customFieldComponents.entrySet()){
			Component comp = e.getValue();
			String value;
			if(comp instanceof JCheckBox)
				value = ((JCheckBox)comp).isSelected() ? "true" : "false";
			else if(comp instanceof JComboBox){
				Object sel = ((JComboBox)comp).getSelectedItem();
				value = sel == null ? "" : sel.toString();
			}else if(comp instanceof JTextField)
				value = ((JTextField)comp).getText();
			else
				value = "";
			obj.put(e.getKey(), value);
		}
		try{
			return URLEncoder.encode(obj.toJSONString(), "UTF-8");
		}catch(UnsupportedEncodingException ex){
			System.out.println(ex.getMessage());
			return "";
		}
	}

	/**
	 * Returns the URL-encoded selected report Section, or "" when none is
	 * selected (e.g. the report-sections endpoint is unavailable) so callers
	 * can skip the parameter.
	 */
	private String sectionValue(){
		if(sections == null || sections.getSelectedItem() == null)
			return "";
		String section = sections.getSelectedItem().toString();
		// "Default" is the implicit section on the backend; sending it explicitly
		// breaks the save, so treat it the same as no section.
		if(section.isEmpty() || section.equalsIgnoreCase("Default"))
			return "";
		try{
			return URLEncoder.encode(section, "UTF-8");
		}catch(UnsupportedEncodingException ex){
			System.out.println(ex.getMessage());
			return "";
		}
	}

	public JCheckBox getOptReq() {
		return optReq;
	}
	public JCheckBox getOptCookies() {
		return optCookies;
	}
	public JCheckBox getOptResp() {
		return optResp;
	}
	public JEditorPane getMessage() {
		return message_1;
	}
	protected JComboBox getDefaultVulns() {
		return defaultVulns;
	}
	
	private boolean isScanItems(IContextMenuInvocation inv){
		byte ctx = inv.getInvocationContext();
		if(ctx == inv.CONTEXT_SCANNER_RESULTS){
			return true;
		}else{
			return false;
		}
	}
	protected JComboBox getSeverity() {
		return severity;
	}
	protected JCheckBox getUseSelected() {
		return useSelected;
	}
}
