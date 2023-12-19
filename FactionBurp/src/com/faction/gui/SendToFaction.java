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
import java.awt.Component;

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
import java.io.UnsupportedEncodingException;
import javax.swing.JScrollPane;

import org.commonmark.node.*;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

public class SendToFaction {

	public JFrame frame;
	private JTextField vulnName;
	private FactionAPI api = new FactionAPI();
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
	private JCheckBox useSelected;
	private LinkedHashMap<String, Integer> levels = new LinkedHashMap();
	private JScrollPane scrollPane;
	private JPanel panel_1;
	private boolean isScan;
	
	

	
	/**
	 * Create the application.
	 */
	public SendToFaction(Object event, boolean isScan, boolean isNew, String appId) {
		this.isNew = isNew;
		this.appId = appId;
		this.event = event;
		this.isScanIssue = isScan;

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
		levels = api.getLevelMap();
		frame = new JFrame();
		//frame.setIconImage(Toolkit.getDefaultToolkit().getImage(SendToFaction.class.getResource("/com/fuse/gui/tri-fuse.png")));
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		frame.setBounds(100, 100, 797, 777);
		//frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 130, 0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE};
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
		
		JComboBox assessmentList = new JComboBox();
		assessmentList.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if(!isNew){
					int index = assessmentList.getSelectedIndex();
					JSONObject obj = (JSONObject)asmts.get(index);
					vulns = api.executeGet(FactionAPI.GETVULNS + obj.get("Id"));
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
					JSONArray jarray = api.executeGet(FactionAPI.SEARCH_DEFAULT_VULN + vulnSearch.getText());
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
		
		severity = new JComboBox();
		severity.setToolTipText("Set the Overall Severity of the issue.");
		String [] severityStrings = api.getSeverityStrings();
		FSUtils.setSeverityComboBoxDefaults(api, severity, FactionAPI.BURP_SEV_HIGH, severityStrings, (updatedSeverityString) ->{});

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
		gbl_panel_1.rowHeights = new int[]{0, 0};
		gbl_panel_1.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		scrollPane = new JScrollPane();
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridwidth = 2;
		gbc_scrollPane.insets = new Insets(0, 0, 0, 5);
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 0;
		panel_1.add(scrollPane, gbc_scrollPane);
		
		message_1 = new JEditorPane();
		scrollPane.setViewportView(message_1);
		message_1.setText("Enter Exploit Steps or Additional Informaiton here");
		message_1.setContentType("text/plain");
		
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
								+ "&severity=" + api.getSevMapping(baseIssue.severity().name());
								api.executePost(FactionAPI.ADDVULN + obj.get("Id"), postData);
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
							if(_defaultVulns.size() > 0){
								JSONObject vobj = _defaultVulns.get(defaultVulns.getSelectedItem());
								api.executePost(FactionAPI.ADDDEFAULTVULN + obj.get("Id") + "/" + vobj.get("Id"), postData);
							}else{
								api.executePost(FactionAPI.ADDVULN + obj.get("Id"), postData);
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
					api.executePost(FactionAPI.ADDVULN + aObj.get("Id") + "/" + vObj.get("Id"), postData);
					
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
		
		asmts = api.executeGet("/assessments/queue");
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
			if( this.optResp.isSelected()){
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
				_message.append("<pre class='code'>");
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				_message.append(data);
				_message.append("</pre>");
			}
			if(this.optResp.isSelected()){
				data = StringEscapeUtils.escapeHtml(response.toString());
				data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
				_message.append("<b>Response: </b>");
				_message.append("<pre class='code'>");
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				_message.append(data);
				_message.append("</pre>");
			}
		});
		return _message.toString();
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
