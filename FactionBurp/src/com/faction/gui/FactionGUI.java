package com.faction.gui;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.JButton;
import javax.swing.JComboBox;

import java.awt.GridLayout;

import javax.swing.JEditorPane;
import javax.swing.JTabbedPane;
import javax.swing.JLabel;
import javax.swing.JTextField;

import java.awt.GridBagLayout;

import javax.swing.JTable;

import java.awt.GridBagConstraints;

import javax.swing.JScrollPane;

import java.awt.Insets;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.faction.api.FactionAPI;
import com.faction.utils.FSUtils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.swing.Box;

import java.awt.Dimension;
import java.awt.Font;

import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.border.LineBorder;
import javax.swing.JPasswordField;
import javax.swing.JSplitPane;

public class FactionGUI extends JPanel implements IExtensionStateListener, ExtensionUnloadingHandler  {

	private JPanel contentPane;
	private JTextField serverTxt;
	private JPasswordField tokenTxt;
	private JTable queueTable;
	private FactionTableModel asmtModel;
	private FactionTableModel vulnModel;
	private FactionTableModel verModel;
	private JTable vulnTable;
	private JTextField asmtName;
	private JEditorPane notesTxt;
	private JEditorPane notes2Txt;
	private LinkedHashMap<String, String> Notes = new LinkedHashMap<>();
	private FactionAPI factionApi;
	private JTextField refreshRate;
	private Timer refreshTimer;
	private String appId = "";
	private JTable verTable;
	private JTextField txtHttpsgithubcomfactionsecurityfaction;
	private JTextField txtHttpswwwfactionsecuritycom;
	private Logging logging;
	private LinkedHashMap<String, Integer> levelMap = new LinkedHashMap<>();


	public void extensionUnloaded(){
		logging.logToOutput("Stoping Timer");
		refreshTimer.cancel();
	}
	/**
	 * Create the frame.
	 */
	public FactionGUI(MontoyaApi api, IBurpExtenderCallbacks legacyCallback) {
		factionApi = new FactionAPI(api);
		logging = api.logging();
		setBounds(100, 100, 1099, 749);
		//contentPane = new JPanel();
		contentPane = this;
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		//setContentPane(contentPane);
		contentPane.setLayout(new GridLayout(1, 0, 0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		contentPane.add(tabbedPane);

		String [] severityStrings = factionApi.getSeverityStrings();
		String vColumnNames[] = { "Start", "Name", "Vulnerability", "Severity", "VulnId" };
		verModel = new FactionTableModel(vColumnNames);
		Vector vvect = new Vector();
		vvect.add("");vvect.add("");vvect.add("");vvect.add("");
		verModel.addRow(vvect);
		
		String columnNames[] = { "AppId", "AppName", "Start Date", "EndDate" };
		asmtModel = new FactionTableModel(columnNames);
		Vector vect = new Vector();
		vect.add("");vect.add("");vect.add("");vect.add("");
		asmtModel.addRow(vect);
		
		
		JSplitPane combinedQueue = new JSplitPane();
		combinedQueue.setResizeWeight(0.5);
		tabbedPane.addTab("Queues", null, combinedQueue, null);
		
		JPanel panel_3 = new JPanel();
		combinedQueue.setRightComponent(panel_3);
		GridBagLayout gbl_panel_3 = new GridBagLayout();
		gbl_panel_3.columnWidths = new int[]{498, 0};
		gbl_panel_3.rowHeights = new int[]{0, 0, 0};
		gbl_panel_3.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_3.rowWeights = new double[]{1.0, 0.0, Double.MIN_VALUE};
		panel_3.setLayout(gbl_panel_3);
		
		JScrollPane scrollPane_3 = new JScrollPane();
		GridBagConstraints gbc_scrollPane_3 = new GridBagConstraints();
		gbc_scrollPane_3.fill = GridBagConstraints.BOTH;
		gbc_scrollPane_3.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPane_3.gridx = 0;
		gbc_scrollPane_3.gridy = 0;
		panel_3.add(scrollPane_3, gbc_scrollPane_3);
		this.updateAPI();
		verTable = new JTable();
		verTable.setAutoCreateRowSorter(true);
		verTable.setModel(verModel);
		verTable.getRowSorter().toggleSortOrder(0);
		verTable.setDefaultRenderer(Object.class, new CustomCellRenderer(this.levelMap));
		verTable.getSelectionModel().addListSelectionListener(
			new ListSelectionListener(){
        	public void valueChanged(ListSelectionEvent event) {
				if(!event.getValueIsAdjusting() && verTable.getSelectedRow() != -1){
			        	int r = verTable.getSelectedRow();
			        	int row = verTable.convertRowIndexToModel(r);
			        	
			        	Long vid = (Long)verModel.getValueAt(row, 4);
			        	JSONArray json = factionApi.executeGet("/assessments/vuln/" + vid);
			        	JSONObject j = (JSONObject)json.get(0);
			        	VulnerabilityDetailsPane test = new VulnerabilityDetailsPane(factionApi,(String)j.get("Name"), (String)j.get("Description"),(String)j.get("Recommendation"), (String)j.get("Details"), legacyCallback);
			        	test.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
			        	test.setSize(900, 1000);
			        	test.setVisible(true);
		        	}
		    }
		});
		
		
		scrollPane_3.setViewportView(verTable);
		
		JPanel panel_4 = new JPanel();
		GridBagConstraints gbc_panel_4 = new GridBagConstraints();
		gbc_panel_4.anchor = GridBagConstraints.WEST;
		gbc_panel_4.fill = GridBagConstraints.VERTICAL;
		gbc_panel_4.gridx = 0;
		gbc_panel_4.gridy = 1;
		panel_3.add(panel_4, gbc_panel_4);
		
		JButton updateVerBtn = new JButton("Refresh");
		panel_4.add(updateVerBtn);
		
		JPanel panel_5 = new JPanel();
		combinedQueue.setLeftComponent(panel_5);
		GridBagLayout gbl_panel_5 = new GridBagLayout();
		gbl_panel_5.columnWidths = new int[]{0, 0};
		gbl_panel_5.rowHeights = new int[]{0, 0, 0};
		gbl_panel_5.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_5.rowWeights = new double[]{1.0, 0.0, Double.MIN_VALUE};
		panel_5.setLayout(gbl_panel_5);
		
		JScrollPane scrollPane_4 = new JScrollPane();
		GridBagConstraints gbc_scrollPane_4 = new GridBagConstraints();
		gbc_scrollPane_4.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPane_4.fill = GridBagConstraints.BOTH;
		gbc_scrollPane_4.gridx = 0;
		gbc_scrollPane_4.gridy = 0;
		panel_5.add(scrollPane_4, gbc_scrollPane_4);
		
		JPanel panel_6 = new JPanel();
		GridBagConstraints gbc_panel_6 = new GridBagConstraints();
		gbc_panel_6.anchor = GridBagConstraints.WEST;
		gbc_panel_6.fill = GridBagConstraints.VERTICAL;
		gbc_panel_6.gridx = 0;
		gbc_panel_6.gridy = 1;
		panel_5.add(panel_6, gbc_panel_6);
		
		JButton btnNewButton = new JButton("Update");
		panel_6.add(btnNewButton);
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				updateAPI();

			}
		});

		queueTable = new JTable();
		queueTable.setAutoCreateRowSorter(true);
		queueTable.setModel(asmtModel);
		queueTable.getRowSorter().toggleSortOrder(2);
		queueTable.getSelectionModel().addListSelectionListener(
			new ListSelectionListener(){
        	public void valueChanged(ListSelectionEvent event) {
				if(!event.getValueIsAdjusting() && queueTable.getSelectedRow() != -1){
					int r = queueTable.getSelectedRow();
					int row = queueTable.convertRowIndexToModel(r);
					
					for(int i = vulnModel.getRowCount()-1; i >=0; i--){
						vulnModel.removeRow(i);
					}
					appId = ""+asmtModel.getValueAt(row, 0);
					asmtName.setText("AppId: " + appId + " - " + asmtModel.getValueAt(row, 1) + " - Start: " + asmtModel.getValueAt(row, 2) + " - End: " + asmtModel.getValueAt(row, 3));
					asmtName.setEditable(false);
					String NotesStr = Notes.get(appId) == null ? "" : ""+Notes.get(appId);
					String [] notes = NotesStr.split("<!--Split-->");
					notesTxt.setText(notes[0]==null? "Nothing to Show" : notes[0]);
					if(notes.length==2)
						notes2Txt.setText(notes[1]==null? "Nothing to Show" : notes[1]);
					JSONArray json = new JSONArray();
					try {
						json = factionApi.executeGet("/assessments/history/" + URLEncoder.encode(appId,"UTF-8"));
					} catch (UnsupportedEncodingException e) {
						e.printStackTrace();
					}
					for(int i = 0; i<json.size(); i++){
						JSONObject obj = (JSONObject) json.get(i);
						Vector v = new Vector();
						v.add(obj.get("Name"));
						v.add(obj.get("OverallStr"));
						v.add(obj.get("ImpactStr"));
						v.add(obj.get("LikelyhoodStr"));
						v.add(obj.get("Opened"));
						v.add(obj.get("Closed"));
						v.add(obj.get("Id"));
						vulnModel.addRow(v);
					}
					
					
					}
			}}
		);
		scrollPane_4.setViewportView(queueTable);
		
		JPanel asmtPanel = new JPanel();
		tabbedPane.addTab("Assessment", null, asmtPanel, null);
		asmtPanel.setLayout(new GridLayout(2, 1, 0, 0));
		
		JScrollPane scrollPane_2 = new JScrollPane();
		asmtPanel.add(scrollPane_2);
		
		JPanel panel_1 = new JPanel();
		scrollPane_2.setViewportView(panel_1);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{0, 0, 0, 0, 0};
		gbl_panel_1.rowHeights = new int[]{0, 0, 0, 0, 0};
		gbl_panel_1.columnWeights = new double[]{0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);
		
		Component rigidArea_4 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_4 = new GridBagConstraints();
		gbc_rigidArea_4.insets = new Insets(0, 0, 5, 0);
		gbc_rigidArea_4.gridx = 3;
		gbc_rigidArea_4.gridy = 0;
		panel_1.add(rigidArea_4, gbc_rigidArea_4);
		
		Component rigidArea_2 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_2 = new GridBagConstraints();
		gbc_rigidArea_2.insets = new Insets(0, 0, 5, 5);
		gbc_rigidArea_2.gridx = 0;
		gbc_rigidArea_2.gridy = 1;
		panel_1.add(rigidArea_2, gbc_rigidArea_2);
		
		JLabel lblName = new JLabel("Name:");
		lblName.setFont(new Font("Arial", Font.BOLD, 18));
		GridBagConstraints gbc_lblName = new GridBagConstraints();
		gbc_lblName.insets = new Insets(0, 0, 5, 5);
		gbc_lblName.gridx = 1;
		gbc_lblName.gridy = 1;
		panel_1.add(lblName, gbc_lblName);
		
		Component rigidArea = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea = new GridBagConstraints();
		gbc_rigidArea.insets = new Insets(0, 0, 5, 5);
		gbc_rigidArea.gridx = 2;
		gbc_rigidArea.gridy = 1;
		panel_1.add(rigidArea, gbc_rigidArea);
		
		asmtName = new JTextField();
		asmtName.setFont(new Font("Arial", Font.BOLD, 15));
		GridBagConstraints gbc_asmtName = new GridBagConstraints();
		gbc_asmtName.insets = new Insets(0, 0, 5, 0);
		gbc_asmtName.fill = GridBagConstraints.HORIZONTAL;
		gbc_asmtName.gridx = 3;
		gbc_asmtName.gridy = 1;
		panel_1.add(asmtName, gbc_asmtName);
		asmtName.setColumns(10);
		
		Component rigidArea_3 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_3 = new GridBagConstraints();
		gbc_rigidArea_3.insets = new Insets(0, 0, 5, 5);
		gbc_rigidArea_3.gridx = 0;
		gbc_rigidArea_3.gridy = 2;
		panel_1.add(rigidArea_3, gbc_rigidArea_3);
		
		JLabel lblNotes = new JLabel("Notes:");
		lblNotes.setFont(new Font("Arial", Font.BOLD, 18));
		GridBagConstraints gbc_lblNotes = new GridBagConstraints();
		gbc_lblNotes.insets = new Insets(0, 0, 5, 5);
		gbc_lblNotes.gridx = 1;
		gbc_lblNotes.gridy = 2;
		panel_1.add(lblNotes, gbc_lblNotes);
		
		Component rigidArea_1 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_1 = new GridBagConstraints();
		gbc_rigidArea_1.insets = new Insets(0, 0, 5, 5);
		gbc_rigidArea_1.gridx = 2;
		gbc_rigidArea_1.gridy = 2;
		panel_1.add(rigidArea_1, gbc_rigidArea_1);
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)), "Assessment Scope/Assessment Notes", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(51, 51, 51)));
		GridBagConstraints gbc_panel_2 = new GridBagConstraints();
		gbc_panel_2.fill = GridBagConstraints.BOTH;
		gbc_panel_2.insets = new Insets(0, 0, 5, 0);
		gbc_panel_2.gridx = 3;
		gbc_panel_2.gridy = 2;
		panel_1.add(panel_2, gbc_panel_2);
		GridBagLayout gbl_panel_2 = new GridBagLayout();
		gbl_panel_2.columnWidths = new int[]{0, 0};
		gbl_panel_2.rowHeights = new int[]{0, 0};
		gbl_panel_2.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_2.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_2.setLayout(gbl_panel_2);
		
		JSplitPane splitPane = new JSplitPane();
		splitPane.setResizeWeight(0.5);
		splitPane.setOneTouchExpandable(true);
		GridBagConstraints gbc_splitPane = new GridBagConstraints();
		gbc_splitPane.fill = GridBagConstraints.BOTH;
		gbc_splitPane.gridx = 0;
		gbc_splitPane.gridy = 0;
		panel_2.add(splitPane, gbc_splitPane);
		
		notesTxt = new JEditorPane();
		splitPane.setLeftComponent(notesTxt);
		notesTxt.setEditable(false);
		notesTxt.setContentType("text/html");
		
		notes2Txt = new JEditorPane();
		notes2Txt.setContentType("text/html");
		splitPane.setRightComponent(notes2Txt);
		
		Component rigidArea_5 = Box.createRigidArea(new Dimension(20, 20));
		GridBagConstraints gbc_rigidArea_5 = new GridBagConstraints();
		gbc_rigidArea_5.gridx = 3;
		gbc_rigidArea_5.gridy = 3;
		panel_1.add(rigidArea_5, gbc_rigidArea_5);
		
		JScrollPane scrollPane_1 = new JScrollPane();
		asmtPanel.add(scrollPane_1);
		
		vulnTable = new JTable();
		String vcolnames[] = { "Name", "Severity", "Impact", "LikelyHood", "Opened", "Closed", "vid" };
		
		vulnModel = new FactionTableModel(vcolnames);
		vulnTable.setAutoCreateRowSorter(true);
		vulnTable.setModel(vulnModel);
		vect = new Vector();
		vect.add("");vect.add("");vect.add("");vect.add("");vect.add("");vect.add("");vect.add("");
		vulnModel.addRow(vect);
		vulnTable.getRowSorter().toggleSortOrder(4);
		vulnTable.getColumnModel().getColumn(1).setMaxWidth(100);
		vulnTable.getColumnModel().getColumn(2).setMaxWidth(100);
		vulnTable.getColumnModel().getColumn(3).setMaxWidth(100);
		vulnTable.getColumnModel().getColumn(4).setMaxWidth(250);
		vulnTable.getColumnModel().getColumn(4).setPreferredWidth(250);
		vulnTable.getColumnModel().getColumn(5).setPreferredWidth(250);
		vulnTable.getColumnModel().getColumn(5).setMaxWidth(250);
		vulnTable.getColumnModel().getColumn(6).setMaxWidth(50);
		
		vulnTable.setDefaultRenderer(Object.class, new CustomCellRenderer(this.levelMap) );
		vulnTable.getSelectionModel().addListSelectionListener(
			new ListSelectionListener(){
        	public void valueChanged(ListSelectionEvent event) {
				if(!event.getValueIsAdjusting() && vulnTable.getSelectedRow() != -1){
			        	int r = vulnTable.getSelectedRow();
			        	int row = vulnTable.convertRowIndexToModel(r);
						Long vid = (Long)vulnModel.getValueAt(row, 6);
						JSONArray json = factionApi.executeGet("/assessments/vuln/" + vid);
						JSONObject j = (JSONObject)json.get(0);
						VulnerabilityDetailsPane test = new VulnerabilityDetailsPane(factionApi,(String)j.get("Name"), j.get("Description").toString(),j.get("Recommendation").toString(),j.get("Details").toString(), legacyCallback);
						test.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
						test.setSize(900, 1000);
						test.setVisible(true);
		        	}
		        	
		        }
		});
		
		scrollPane_1.setViewportView(vulnTable);
		
		JPanel ConfigPanel = new JPanel();
		tabbedPane.addTab("Config", null, ConfigPanel, null);
		ConfigPanel.setLayout(null);
		
		JLabel lblServer = new JLabel("Server:");
		lblServer.setBounds(32, 54, 60, 15);
		ConfigPanel.add(lblServer);
		
		JLabel lblToken = new JLabel("Token:");
		lblToken.setBounds(32, 97, 60, 15);
		ConfigPanel.add(lblToken);
		
		serverTxt = new JTextField();
		serverTxt.setBounds(88, 48, 336, 27);
		ConfigPanel.add(serverTxt);
		serverTxt.setColumns(10);
		
		tokenTxt = new JPasswordField();
		tokenTxt.setBounds(88, 91, 336, 27);
		ConfigPanel.add(tokenTxt);
		tokenTxt.setColumns(10);
		
		JButton updateBtn = new JButton("Refresh");
		updateBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				factionApi.updateProps(serverTxt.getText(), tokenTxt.getText(), refreshRate.getText());
				try{
				refreshTimer.cancel();
				}catch(Exception ex){}
				refreshTimer = new Timer();
				refreshTimer.scheduleAtFixedRate(new TimerTask(){
					@Override
					public void run() {
						updateAPI();
						
					}}, 0, 1000 * factionApi.getRefresh());
				

			}
		});
		updateBtn.setBounds(305, 129, 117, 25);
		ConfigPanel.add(updateBtn);
		
		serverTxt.setText(factionApi.getServer());
		tokenTxt.setText(factionApi.getToken());
		
		
		
				
				
				JLabel lblRefresh = new JLabel("Refresh:");
				lblRefresh.setBounds(32, 134, 46, 25);
				ConfigPanel.add(lblRefresh);
				
				refreshRate = new JTextField();
				refreshRate.setText("20");
				refreshRate.setBounds(88, 129, 46, 25);
				ConfigPanel.add(refreshRate);
				refreshRate.setColumns(10);
				refreshRate.setText("" + factionApi.getRefresh());
				
				JLabel lblSecs = new JLabel("Seconds");
				lblSecs.setBounds(144, 134, 100, 20);
				ConfigPanel.add(lblSecs);
				
				JLabel lblNewLabel = new JLabel("Burp to Faction Severity Mapping");
				lblNewLabel.setFont(new Font("Lucida Grande", Font.BOLD, 18));
				lblNewLabel.setBounds(32, 166, 392, 31);
				ConfigPanel.add(lblNewLabel);
				
				JLabel lblNewLabel_1 = new JLabel("Burp HIGH");
				lblNewLabel_1.setBounds(140, 213, 100, 16);
				ConfigPanel.add(lblNewLabel_1);
				
				JLabel lblNewLabel_2 = new JLabel("Burp MEDIUM");
				lblNewLabel_2.setBounds(140, 245, 103, 16);
				ConfigPanel.add(lblNewLabel_2);
				
				JLabel lblNewLabel_3 = new JLabel("Burp LOW");
				lblNewLabel_3.setBounds(140, 277, 102, 16);
				ConfigPanel.add(lblNewLabel_3);
				
				JLabel lblNewLabel_4 = new JLabel("Burp INFORMATION");
				lblNewLabel_4.setBounds(140, 309, 168, 16);
				ConfigPanel.add(lblNewLabel_4);
				JComboBox sevMapMed = new JComboBox();
				FSUtils.setSeverityComboBoxDefaults(factionApi, sevMapMed,FactionAPI.BURP_SEV_MED,severityStrings, (selectedSev) ->{
					factionApi.updateSev(FactionAPI.BURP_SEV_MED, selectedSev);
				} );
				sevMapMed.setBounds(32, 241, 104, 27);
				ConfigPanel.add(sevMapMed);
				
				JComboBox sevMapHigh = new JComboBox();
				FSUtils.setSeverityComboBoxDefaults(factionApi, sevMapHigh,FactionAPI.BURP_SEV_HIGH,severityStrings, (selectedSev) ->
				factionApi.updateSev(FactionAPI.BURP_SEV_HIGH, selectedSev) );
				sevMapHigh.setBounds(32, 209, 104, 27);
				ConfigPanel.add(sevMapHigh);
				
				JComboBox sevMapLow = new JComboBox();
				FSUtils.setSeverityComboBoxDefaults(factionApi, sevMapLow,FactionAPI.BURP_SEV_LOW,severityStrings, (selectedSev) ->
				factionApi.updateSev(FactionAPI.BURP_SEV_LOW, selectedSev) );
				sevMapLow.setBounds(32, 273, 104, 27);
				ConfigPanel.add(sevMapLow);
				
				JComboBox sevMapInfo = new JComboBox();
				FSUtils.setSeverityComboBoxDefaults(factionApi, sevMapInfo,FactionAPI.BURP_SEV_INFO,severityStrings, (selectedSev) ->
				factionApi.updateSev(FactionAPI.BURP_SEV_INFO, selectedSev) );
				sevMapInfo.setBounds(32, 305, 104, 27);
				ConfigPanel.add(sevMapInfo);
				
				JLabel lblNewLabel_5 = new JLabel("Faction - Open Source Assessment Collaboration");
				lblNewLabel_5.setFont(new Font("Lucida Grande", Font.BOLD, 18));
				lblNewLabel_5.setBounds(514, 48, 512, 21);
				ConfigPanel.add(lblNewLabel_5);
				
				JLabel lblNewLabel_6 = new JLabel("GitHub");
				lblNewLabel_6.setBounds(514, 96, 61, 16);
				ConfigPanel.add(lblNewLabel_6);
				
				txtHttpsgithubcomfactionsecurityfaction = new JTextField();
				txtHttpsgithubcomfactionsecurityfaction.setText("https://github.com/factionsecurity/faction");
				txtHttpsgithubcomfactionsecurityfaction.setBounds(587, 91, 439, 26);
				ConfigPanel.add(txtHttpsgithubcomfactionsecurityfaction);
				txtHttpsgithubcomfactionsecurityfaction.setColumns(10);
				
				JLabel lblNewLabel_7 = new JLabel("WebSite");
				lblNewLabel_7.setBounds(514, 132, 61, 16);
				ConfigPanel.add(lblNewLabel_7);
				
				txtHttpswwwfactionsecuritycom = new JTextField();
				txtHttpswwwfactionsecuritycom.setText("https://www.factionsecurity.com");
				txtHttpswwwfactionsecuritycom.setColumns(10);
				txtHttpswwwfactionsecuritycom.setBounds(587, 127, 439, 26);
				ConfigPanel.add(txtHttpswwwfactionsecuritycom);
				
				JLabel lblNewLabel_8 = new JLabel("Server Configuration");
				lblNewLabel_8.setFont(new Font("Lucida Grande", Font.BOLD, 18));
				lblNewLabel_8.setBounds(32, 20, 392, 16);
				ConfigPanel.add(lblNewLabel_8);
		
		
		
		
		refreshTimer = new Timer();
		refreshTimer.scheduleAtFixedRate(new TimerTask(){

			@Override
			public void run() {
				updateAPI();
				
			}}, 0, 1000 * factionApi.getRefresh());
		
		
	}
	
	private synchronized void  updateAPI() {
		levelMap = factionApi.getLevelMap();	
		/*
		 * Get Verification Queue
		 */
		JSONArray vjson = factionApi.executeGet(FactionAPI.VQUEUE);
		if(vjson != null){
			
			for(int i = verModel.getRowCount()-1; i >=0; i--){
				verModel.removeRow(i);
				
			}
			for(int i = 0 ; i< vjson.size(); i++){
				JSONObject obj = (JSONObject)vjson.get(i);
				Vector vect = new Vector();
				vect.add(convertDate((String)obj.get("Start")));
				vect.add(obj.get("AssessmentName"));
				vect.add(obj.get("Name"));
				vect.add(obj.get("OverallStr"));
				vect.add(obj.get("Id"));
				verModel.addRow(vect);
			}
		}
			
		/*
		 * Get Assessment Queue	
		 */
		JSONArray json = factionApi.executeGet(FactionAPI.QUEUE);
		if(json == null)
			return;
		/*
		 * Update Assessment information.
		 */
		for(int i = 0 ; i< json.size(); i++){
			JSONObject obj = (JSONObject)json.get(i);
			Vector vect = new Vector();
			String appId = (String) obj.get("AppId");
			vect.add(appId);
			vect.add(obj.get("Name"));
			vect.add(convertDate((String)obj.get("Start")));
			vect.add(convertDate((String)obj.get("End")));
			boolean found = false;	
			for(int j = 0; j< asmtModel.getRowCount(); j++){
				String id = (String) asmtModel.getValueAt(j, 0);
				if(id.equals(appId)){
					found = true;
					break;
				}
			}
			if(!found){
				asmtModel.addRow(vect);
			}
			String creds = obj.get("AccessNotes") == null ? "" : (String)obj.get("AccessNotes");
			String notes = obj.get("Notes") == null ? "" : (String)obj.get("Notes");
			Notes.put(appId, creds + "<!--Split-->" + notes);
		}
		/*
		 * Check if we need to remove any assessments
		 */
		for(int j =asmtModel.getRowCount()-1; j>=0; j--){
			boolean found = false;
			String appId = ""+asmtModel.getValueAt(j, 0);
			for(int i = 0; i<json.size(); i++){
				JSONObject obj = (JSONObject) json.get(i);
				String jsonId = ""+obj.get("AppId");
				if(appId.equals(jsonId)){
					found = true;
					break;
				}
			}
			if(!found){
				asmtModel.removeRow(j);
			}
		}

		/*
		 * Add Only new findings to the table if an application is selected.
		 */
		if(!appId.equals("")){
			JSONArray vulns = new JSONArray();
			try {
				vulns = factionApi.executeGet("/assessments/history/" + URLEncoder.encode(appId,"UTF-8"));
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	for(int i = 0; i<vulns.size(); i++){
        		JSONObject obj = (JSONObject) vulns.get(i);
        		Vector v = new Vector();
        		v.add(obj.get("Name"));
        		v.add(obj.get("OverallStr"));
        		v.add(obj.get("ImpactStr"));
        		v.add(obj.get("LikelyhoodStr"));
        		v.add(obj.get("Opened"));
        		v.add(obj.get("Closed"));
        		v.add(obj.get("Id"));
        		boolean found=false;
        		
        		for(int j =0; j<vulnModel.getRowCount(); j++){
        			if((""+vulnModel.getValueAt(j, 6)).equals(""+v.get(6))){
        				found = true;
        				break;
        			}
        		}
        		
        		if(!found){
        			vulnModel.insertRow(0, v);
        		}
        	}
        	//remove vulns no longer in table
        	for(int j =vulnModel.getRowCount()-1; j>=0; j--){
        		boolean found = false;
        		for(int i = 0; i<vulns.size(); i++){
            		JSONObject obj = (JSONObject) vulns.get(i);
            		
            		if((""+vulnModel.getValueAt(j, 6)).equals(""+obj.get("Id"))){
            			
            			found = true;
        				break;
            		}
        		}
    			if(!found){
    				vulnModel.removeRow(j);
    				
    			}
    		}
		}
		
	}
	
	
	public static String convertDate(String date){
		SimpleDateFormat sdf1 = new SimpleDateFormat("MMM dd HH:mm:ss zzz yyyy");
		SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
		try {
			Calendar c = Calendar.getInstance();
			c.setTimeInMillis(Long.parseLong(date));
			return sdf2.format(c.getTime());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
		
	}
	public String getAppId(){
		return this.appId;
	}

	public FactionAPI getFactionApi(){
		return this.factionApi;
	}
}
