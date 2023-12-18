package com.fuse.gui;

import java.awt.EventQueue;

import javax.swing.JFrame;
import java.awt.GridBagLayout;
import javax.swing.JLabel;
import java.awt.GridBagConstraints;
import javax.swing.JComboBox;
import java.awt.Insets;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.fuse.api.FuseAPI;
import com.sun.jersey.core.util.Base64;
import com.sun.jersey.impl.ApiMessages;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
//import flex.messaging.util.URLEncoder;
import java.net.URLEncoder;

import java.awt.FlowLayout;
import javax.swing.JEditorPane;
import javax.swing.JCheckBox;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JTextArea;
import java.awt.Component;

import javax.print.attribute.standard.Severity;
import javax.swing.Box;
import java.awt.Dimension;
import javax.swing.JTextField;
import javax.swing.border.LineBorder;
import java.awt.Color;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.sql.Savepoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.awt.event.ActionEvent;
import javax.swing.DefaultComboBoxModel;
import javax.swing.border.EtchedBorder;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.UnsupportedEncodingException;
import java.awt.Toolkit;
import javax.swing.JScrollPane;

import org.commonmark.node.*;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

public class SendToFaction {

	public JFrame frame;
	private JTextField vulnName;
	private FuseAPI api = new FuseAPI();
	private JSONArray asmts;
	private JSONArray vulns;
	private IBurpExtenderCallbacks cb;
	private JCheckBox optReq;
	private JCheckBox optCookies;
	private JCheckBox optResp;
	private JCheckBox optFeed;
	private JEditorPane message_1;
	private IContextMenuInvocation inv;
	private JComboBox vulnList;
	private JButton btnSave;
	private boolean isScanIssue=false;
	private boolean newVuln = true;
	private HashMap<String,List<IScanIssue>>scanIssues;
	private JTextField vulnSearch;
	private JComboBox defaultVulns;
	private HashMap<String, JSONObject> _defaultVulns = new HashMap<String,JSONObject>();
	private String APPID;
	private JComboBox severity;
	private JCheckBox useSelected;
	private HashMap<String, Integer> levels = new HashMap();
	private JScrollPane scrollPane;
	private JPanel panel_1;
	
	

	
	/**
	 * Create the application.
	 */
	public SendToFaction(IBurpExtenderCallbacks cb, IContextMenuInvocation inv, boolean newVuln, String appid) {
		this.cb = cb;
		this.inv = inv;
		this.newVuln=newVuln;
		this.APPID = appid;
		if(inv.CONTEXT_SCANNER_RESULTS == inv.getInvocationContext()){
			this.isScanIssue = true;
			IScanIssue scans [] = inv.getSelectedIssues();
			scanIssues = new HashMap();
			for(IScanIssue scan :scans){
				if(scanIssues.containsKey(scan.getIssueName()))
						scanIssues.get(scan.getIssueName()).add(scan);
				else{
					List<IScanIssue> newList = new ArrayList<IScanIssue>();
					newList.add(scan);
					scanIssues.put(scan.getIssueName(), newList);
				}
			}
		}
			
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
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
		if(newVuln){
			JLabel lblName = new JLabel("Name:");
			GridBagConstraints gbc_lblName = new GridBagConstraints();
			gbc_lblName.anchor = GridBagConstraints.EAST;
			gbc_lblName.insets = new Insets(0, 0, 5, 5);
			gbc_lblName.gridx = 1;
			gbc_lblName.gridy = 1;
			frame.getContentPane().add(lblName, gbc_lblName);
			
			vulnName = new JTextField();
			if(inv.getSelectedIssues() != null){
				if(inv.getSelectedIssues().length == 1)
					vulnName.setText(inv.getSelectedIssues()[0].getIssueName());
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
				if(!newVuln){
					int index = assessmentList.getSelectedIndex();
					JSONObject obj = (JSONObject)asmts.get(index);
					vulns = api.executeGet(FuseAPI.GETVULNS + obj.get("Id"));
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
		
		if(!newVuln){
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
		
		if(!newVuln || isScanItems(inv)){
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
					JSONArray jarray = api.executeGet(FuseAPI.SEARCH_DEFAULT_VULN + vulnSearch.getText());
					if(defaultVulns.getItemCount() > 0){
						defaultVulns.removeAllItems();
						_defaultVulns.clear();
					}
					for(int i=0; i< jarray.size();i++){
						JSONObject obj = (JSONObject)jarray.get(i);
						defaultVulns.addItem(""+obj.get("Name"));
						_defaultVulns.put(""+obj.get("Name"), obj);
						//severity.setSelectedIndex(((Long)obj.get("Overall")).intValue());
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
		
		optFeed = new JCheckBox("Show on Feed");
		optFeed.setToolTipText("This will also post the issue to the Live Feed so that everyone working on the assessment can see what you have found.");
		GridBagConstraints gbc_optFeed = new GridBagConstraints();
		gbc_optFeed.anchor = GridBagConstraints.WEST;
		gbc_optFeed.insets = new Insets(0, 0, 5, 5);
		gbc_optFeed.gridx = 3;
		gbc_optFeed.gridy = 0;
		panel.add(optFeed, gbc_optFeed);
		
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
		JSONArray array = api.executeGet(FuseAPI.LEVELS);
		List<String>levelStr = new ArrayList();
		for(int i=0; i< array.size(); i++){
			JSONObject obj = (JSONObject)array.get(i);
			if((""+obj.get("name")).equals(""))
				continue;
			levels.put(""+obj.get("name"), ((Long)obj.get("id")).intValue());
			levelStr.add(""+obj.get("name"));
		}
		//new String[] {"Informational", "Recommended", "Low", "Medium", "High", "Critical"}
		severity.setModel(new DefaultComboBoxModel(levelStr.toArray()));
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
				
				if(newVuln){
					if(inv.getSelectedIssues() !=null){ // we are using scan issues
						
						for(int scanIndex = 0; scanIndex < inv.getSelectedIssues().length; scanIndex++){
							IScanIssue issue = inv.getSelectedIssues()[scanIndex];
							String name = issue.getIssueName();
							int index = assessmentList.getSelectedIndex();
							JSONObject obj = (JSONObject)asmts.get(index);
							String feed="false";
							if(optFeed.isSelected())
								feed = "true";
							String b64 = new String(Base64.encode(createScanMessage(scanIndex)));
							try{
								String postData = "name="+ URLEncoder.encode(name, "UTF-8") + "&feed=" + feed + "&message=" +URLEncoder.encode(b64, "UTF-8");
								//postData+="&severity=" + FuseAPI.setSeverity(""+inv.getSelectedIssues()[scanIndex].getSeverity());
								postData+="&severity=" + levels.get(inv.getSelectedIssues()[scanIndex].getSeverity());
								api.executePost(FuseAPI.ADDVULN + obj.get("Id"), postData);
							} catch (UnsupportedEncodingException ex){
								System.out.println(ex.getMessage());
							}
							
						}
					}else{ // adding a new vuln
						String b64 = new String(Base64.encode(createMessage()));
						String name = vulnName.getText();
						int index = assessmentList.getSelectedIndex();
						JSONObject obj = (JSONObject)asmts.get(index);
						String feed="false";
						if(optFeed.isSelected())
							feed = "true";
						String postData = "name="+ URLEncoder.encode(name) + "&feed=" + feed + "&message=" +URLEncoder.encode(b64);
						//postData+="&severity=" + FuseAPI.setSeverity(""+severity.getSelectedItem());
						postData+="&severity=" + levels.get(""+severity.getSelectedItem());
						if(_defaultVulns.size() > 0){
							JSONObject vobj = _defaultVulns.get(defaultVulns.getSelectedItem());
							api.executePost(FuseAPI.ADDDEFAULTVULN + obj.get("Id") + "/" + vobj.get("Id"), postData);
						}else{
							api.executePost(FuseAPI.ADDVULN + obj.get("Id"), postData);
						}
						
					}
				}else{  // adding an existing vuln
					String b64 = new String(Base64.encode(createMessage()));
					int aindex = assessmentList.getSelectedIndex();
					int vindex  = vulnList.getSelectedIndex();
					JSONObject aObj = (JSONObject)asmts.get(aindex);
					JSONObject vObj = (JSONObject)vulns.get(vindex);
					String feed="false";
					if(optFeed.isSelected())
						feed = "true";
					String postData = "feed=" + feed + "&message=" +URLEncoder.encode(b64);
					//postData+="&severity=" + FuseAPI.setSeverity(""+severity.getSelectedItem());
					postData+="&severity=" + levels.get(""+severity.getSelectedItem());
					api.executePost(FuseAPI.ADDVULN + aObj.get("Id") + "/" + vObj.get("Id"), postData);
					
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
			if(this.APPID != null && (""+obj.get("AppId")).equals(this.APPID) )
				assessmentList.setSelectedIndex(i);
		}
		
		
	}
	
	private String createScanMessage(int scanIndex){
		String message = this.getMessage().getText();
		
		message = message.replaceAll("\r\n", "<br/>").replaceAll("\n", "<br/>");
		message +="<br/>";
		String issueDetail = inv.getSelectedIssues()[scanIndex].getIssueDetail();
		if(issueDetail != null)
			message += issueDetail;
		
		for( IHttpRequestResponse reqres : inv.getSelectedIssues()[scanIndex].getHttpMessages()){
			message +="";
			
			if(this.optReq.isSelected()){
				
				if(reqres.getRequest() != null && !(new String(reqres.getRequest()).trim().equals(""))){
					String req = new String(reqres.getRequest());
			    	message += "";
					//message +="<div class='code' style='background:#eee;border:1px solid #ccc;padding:5px 10px;'>";
					message += "<b>Request: </b>";
					message += "<pre class='code'>";
					if(this.optCookies.isSelected()){
						int start = req.indexOf("Cookie: ");
						if(start != -1){
							start = start +  "Cookie: ".length()-1;
							int end = req.indexOf("\n", start);
							String begin = req.substring(0,start);
							String finish = req.substring(end);
							req = begin + "[ ...snip... ]" + finish;
						}
					}
					String data = StringEscapeUtils.escapeHtml(req);
					data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
					data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
					message += data;
					message += "</pre>";
					//message += "</div>";
			    }
			}
			
			if(this.optResp.isSelected()){
				if(reqres.getResponse() != null && !(new String(reqres.getResponse()).trim().equals(""))){
					String resp = new String(reqres.getResponse());
					message +="";
					//message +="<div class='code' style='background:#eee;border:1px solid #ccc;padding:5px 10px;'>";
					message += "<b>Response: </b>";
					message += "<pre class='code'>";
					if(this.optCookies.isSelected()){
						int start = resp.indexOf("Set-Cookie: ");
						if(start != -1){
							start = start + "Set-Cookie: ".length()-1;
							int end = resp.indexOf("\n", start);
							String begin = resp.substring(0,start);
							String finish = resp.substring(end);
							resp = begin + "[ ...snip... ]" + finish;
						}
					}
					String data = StringEscapeUtils.escapeHtml(resp);
					data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
					data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
					message += data;
					message += "</pre>";
					//message += "</div>";
				}
			}
				
			
		}
		return message;
		
		
	}
	private String createMessage(){
		String message = this.getMessage().getText();
		Parser parser = Parser.builder().build();
		Node document = parser.parse(message);
		HtmlRenderer renderer = HtmlRenderer.builder().build();
		message = renderer.render(document);
		message = message.replaceAll("<code>", "<pre>").replaceAll("</code>", "</pre>");
		message = message.replaceAll("</p>", "<br/>");
		message +="<br>";
		if(this.optReq.isSelected()){
			IHttpRequestResponse  req = inv.getSelectedMessages()[0];
			
			if(req.getRequest() != null){
				String tmp = "";
				if(useSelected.isSelected() && inv.getSelectionBounds() != null && 
						(inv.getInvocationContext() == inv.CONTEXT_MESSAGE_EDITOR_REQUEST ||inv.getInvocationContext() == inv.CONTEXT_MESSAGE_VIEWER_REQUEST)){
					int xy [] = inv.getSelectionBounds();
					byte [] selectedText = Arrays.copyOfRange(req.getRequest(), xy[0], xy[1]);
					
					tmp = new String (selectedText);
					if(xy[0] != 0)
						tmp = "[ ...snip... ]\r\n" + tmp + "\r\n[ ...snip... ]\r\n";
					else
						tmp = tmp + "\r\n[ ...snip... ]\r\n";
					
				}else
					tmp = new String(req.getRequest());
				
				if(tmp == null || tmp.equals(""))
					tmp = new String(req.getRequest());
				
				message +="";
				//message +="<div class='code' style='background:#eee;border:1px solid #ccc;padding:5px 10px;'>";
				message += "<b>Request: </b>";
				message += "<pre class='code'>";
				
				if(this.optCookies.isSelected()){
					int start = tmp.indexOf("Cookie: ");
					if(start != -1){
						start = start +  "Cookie: ".length()-1;
						int end = tmp.indexOf("\r", start);
						String begin = tmp.substring(0,start);
						String finish = tmp.substring(end);
						tmp = begin + "[ ...snip... ]" + finish;
					}
				}
					
				String data = StringEscapeUtils.escapeHtml(tmp);
				data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
				
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				message += data;
				message += "</pre>";
				//message += "</div>";
			}
		}
		if(this.optResp.isSelected()){
			IHttpRequestResponse  req = inv.getSelectedMessages()[0];

			
			if(req.getResponse() != null && !(new String(req.getResponse()).trim().equals(""))){
				String tmp = new String(req.getResponse());
				if(useSelected.isSelected() && inv.getSelectionBounds() != null && 
						(inv.getInvocationContext() == inv.CONTEXT_MESSAGE_EDITOR_RESPONSE || inv.getInvocationContext() == inv.CONTEXT_MESSAGE_VIEWER_RESPONSE)){
					int xy [] = inv.getSelectionBounds();
					byte [] selectedText = Arrays.copyOfRange(req.getResponse(), xy[0], xy[1]);
					tmp = new String (selectedText);
					if(xy[0] != 0)
						tmp = "[ ...snip... ]\r\n" + tmp + "\r\n[ ...snip... ]\r\n";
					else
						tmp = tmp + "\r\n[ ...snip... ]\r\n";
				}else
					tmp = new String(req.getResponse());
				
				if(tmp == null || tmp.equals(""))
					tmp = new String(req.getResponse());
				
				message +="";
				//message +="<div class='code' style='background:#eee;border:1px solid #ccc;padding:5px 10px;'>";
				message += "<b>Response: </b>";
				message += "<pre class='code'>";
				
				if(this.optCookies.isSelected()){
					int start = tmp.indexOf("Set-Cookie: ");
					if(start != -1){
						start = start + "Set-Cookie: ".length()-1;
						int end = tmp.indexOf("\r", start);
						String begin = tmp.substring(0,start);
						String finish = tmp.substring(end);
						tmp = begin + "[ ...snip... ]" + finish;
					}
				}
				
				String data = StringEscapeUtils.escapeHtml(tmp);
				data = data.replaceAll("\r", "").replaceAll("\n", "<br/>");
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				message += data;
				message += "</pre>";
				//message += "</div>";
			}
			
		}
		return message;
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
	public JCheckBox getOptViewState() {
		return optFeed;
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
