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
import flex.messaging.util.URLEncoder;

import java.awt.FlowLayout;
import javax.swing.JEditorPane;
import javax.swing.JCheckBox;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JTextArea;
import java.awt.Component;
import javax.swing.Box;
import java.awt.Dimension;
import javax.swing.JTextField;
import javax.swing.border.LineBorder;
import java.awt.Color;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.sql.Savepoint;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.awt.event.ActionEvent;
import javax.swing.DefaultComboBoxModel;

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
	
	

	
	/**
	 * Create the application.
	 */
	public SendToFaction(IBurpExtenderCallbacks cb, IContextMenuInvocation inv, boolean newVuln) {
		this.cb = cb;
		this.inv = inv;
		this.newVuln=newVuln;
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
		frame.setBounds(100, 100, 669, 405);
		//frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 97, 0, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 1, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, Double.MIN_VALUE};
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
		gbc_lblAssessment.insets = new Insets(0, 0, 5, 5);
		gbc_lblAssessment.anchor = GridBagConstraints.EAST;
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
		
		Component rigidArea = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea = new GridBagConstraints();
		gbc_rigidArea.insets = new Insets(0, 0, 5, 5);
		gbc_rigidArea.gridx = 0;
		gbc_rigidArea.gridy = 4;
		frame.getContentPane().add(rigidArea, gbc_rigidArea);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new LineBorder(new Color(192, 192, 192)), "Options", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(59, 59, 59)));
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.insets = new Insets(0, 0, 5, 5);
		gbc_panel.gridwidth = 2;
		gbc_panel.fill = GridBagConstraints.BOTH;
		gbc_panel.gridx = 1;
		gbc_panel.gridy = 4;
		frame.getContentPane().add(panel, gbc_panel);
		
		optReq = new JCheckBox("Request");
		optReq.setSelected(true);
		
		optCookies = new JCheckBox("Snip Cookies");
		optCookies.setSelected(true);
		
		optResp = new JCheckBox("Response");
		
		optFeed = new JCheckBox("Show on Feed");
		panel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		panel.add(optReq);
		panel.add(optCookies);
		panel.add(optResp);
		panel.add(optFeed);
		
		JComboBox severity = new JComboBox();
		severity.setModel(new DefaultComboBoxModel(new String[] {"Informational", "Recommended", "Low", "Medium", "High", "Critical"}));
		panel.add(severity);
		
		Component rigidArea_1 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_1 = new GridBagConstraints();
		gbc_rigidArea_1.insets = new Insets(0, 0, 5, 0);
		gbc_rigidArea_1.gridx = 3;
		gbc_rigidArea_1.gridy = 4;
		frame.getContentPane().add(rigidArea_1, gbc_rigidArea_1);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new TitledBorder(new LineBorder(new Color(171, 173, 179)), "Message", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		GridBagConstraints gbc_panel_1 = new GridBagConstraints();
		gbc_panel_1.gridwidth = 2;
		gbc_panel_1.insets = new Insets(0, 0, 5, 5);
		gbc_panel_1.fill = GridBagConstraints.BOTH;
		gbc_panel_1.gridx = 1;
		gbc_panel_1.gridy = 5;
		frame.getContentPane().add(panel_1, gbc_panel_1);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{291, 0};
		gbl_panel_1.rowHeights = new int[]{25, 0};
		gbl_panel_1.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		message_1 = new JEditorPane();
		message_1.setText("Enter Exploit Steps or Additional Informaiton here");
		message_1.setContentType("text/plain");
		GridBagConstraints gbc_message_1 = new GridBagConstraints();
		gbc_message_1.fill = GridBagConstraints.BOTH;
		gbc_message_1.gridx = 0;
		gbc_message_1.gridy = 0;
		panel_1.add(message_1, gbc_message_1);
		
		btnSave = new JButton("Save");
		/*
		 * This is the action listener that saves a new vuln
		 * to FACTION
		 */
		btnSave.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String msg = message_1.getText();
				String b64 = new String(Base64.encode(createMessage()));
				if(newVuln){
					String name = vulnName.getText();
					int index = assessmentList.getSelectedIndex();
					JSONObject obj = (JSONObject)asmts.get(index);
					String feed="false";
					if(optFeed.isSelected())
						feed = "true";
					String postData = "name="+ URLEncoder.encode(name) + "&feed=" + feed + "&message=" +URLEncoder.encode(b64);
					postData+="&severity=" + FuseAPI.setSeverity(""+severity.getSelectedItem());
					api.executePost(FuseAPI.ADDVULN + obj.get("Id"), postData);
				}else{
					
					int aindex = assessmentList.getSelectedIndex();
					int vindex  = vulnList.getSelectedIndex();
					JSONObject aObj = (JSONObject)asmts.get(aindex);
					JSONObject vObj = (JSONObject)vulns.get(vindex);
					String feed="false";
					if(optFeed.isSelected())
						feed = "true";
					String postData = "feed=" + feed + "&message=" +URLEncoder.encode(b64);
					postData+="&severity=" + FuseAPI.setSeverity(""+severity.getSelectedItem());
					api.executePost(FuseAPI.ADDVULN + aObj.get("Id") + "/" + vObj.get("Id"), postData);
					
				}
				
				frame.dispose();
			}
		});
		GridBagConstraints gbc_btnSave = new GridBagConstraints();
		gbc_btnSave.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnSave.insets = new Insets(0, 0, 5, 5);
		gbc_btnSave.gridx = 1;
		gbc_btnSave.gridy = 6;
		frame.getContentPane().add(btnSave, gbc_btnSave);
		
		Component rigidArea_3 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_3 = new GridBagConstraints();
		gbc_rigidArea_3.insets = new Insets(0, 0, 0, 5);
		gbc_rigidArea_3.gridx = 2;
		gbc_rigidArea_3.gridy = 7;
		frame.getContentPane().add(rigidArea_3, gbc_rigidArea_3);
		
		asmts = api.executeGet("/assessments/queue");
		for(int i=0; i< asmts.size(); i++){
			JSONObject obj = (JSONObject)asmts.get(i);
			assessmentList.addItem(obj.get("AppId") + " " + obj.get("Name"));
		}
		
		
	}
	private String createMessage(){
		String message = this.getMessage().getText();
		message = message.replace("\r\n", "<br>").replace("\n", "<br>");
		message +="<br>";
		if(this.optReq.isSelected()){
			IHttpRequestResponse  req = inv.getSelectedMessages()[0];
			String tmp = new String(req.getRequest());
			if(tmp!= null && !tmp.trim().equals("")){
				message +="";
				message += "<b>Request: </b>";
				message +="<div class='code' style='background:#eee;border:1px solid #ccc;padding:5px 10px;'>";
				message += "<pre class='code'>";
				
				if(this.optCookies.isSelected()){
					int start = tmp.indexOf("Cookie: ");
					if(start != -1){
						start = start +  "Cookie: ".length();
						int end = tmp.indexOf("\n", start);
						String begin = tmp.substring(0,start);
						String finish = tmp.substring(end);
						tmp = begin + "[ ...snip... ]" + finish;
					}
				}
					
				String data = StringEscapeUtils.escapeHtml(tmp);
				
				data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
				message += data;
				message += "</pre></div>";
			}
		}
		if(this.optResp.isSelected()){
			IHttpRequestResponse  req = inv.getSelectedMessages()[0];
			String tmp = new String(req.getResponse());
			if(tmp!= null && !tmp.trim().equals("")){
				message +="";
				message += "<b>Response: </b>";
				message +="<div class='code' style='background:#eee;border:1px solid #ccc;padding:5px 10px;'>";
				message += "<pre class='code'>";
				
				if(this.optCookies.isSelected()){
					int start = tmp.indexOf("Set-Cookie: ");
					if(start != -1){
						start = start + "Set-Cookie: ".length();
						int end = tmp.indexOf("\n", start);
						String begin = tmp.substring(0,start);
						String finish = tmp.substring(end);
						tmp = begin + "[ ...snip... ]" + finish;
					}
				}
				
				String data = StringEscapeUtils.escapeHtml(tmp);
				message += data;
				message += "</pre></div>";
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
}
