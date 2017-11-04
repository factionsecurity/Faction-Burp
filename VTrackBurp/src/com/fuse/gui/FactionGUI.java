package com.fuse.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.JButton;

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
import java.awt.Toolkit;
import java.awt.FlowLayout;

import javax.swing.SwingConstants;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.fuse.api.FuseAPI;

import burp.IBurpExtenderCallbacks;


import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.swing.JTextArea;
import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.Clip;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.SourceDataLine;
import javax.sound.sampled.UnsupportedAudioFileException;
import javax.swing.Box;

import java.awt.Dimension;
import java.awt.Font;

import javax.swing.border.TitledBorder;
import javax.swing.border.LineBorder;
import javax.swing.JPasswordField;
import javax.swing.JSplitPane;

public class FactionGUI extends JPanel  {

	private JPanel contentPane;
	private JTextField serverTxt;
	private JPasswordField tokenTxt;
	private JTable queueTable;
	private VTTableModel asmtModel;
	private VTTableModel vulnModel;
	private VTTableModel verModel;
	private JTable vulnTable;
	private JTextField asmtName;
	private JEditorPane notesTxt;
	private JEditorPane notes2Txt;
	private List<String> Notes = new ArrayList<String>();
	private FuseAPI api = new FuseAPI();
	private JTextField refreshRate;
	private Timer refreshTimer;
	private String appId = "";
	private JTable verTable;



	/**
	 * Create the frame.
	 */
	public FactionGUI(IBurpExtenderCallbacks cb) {
		//com.fuse.data.Handler.install();
		//setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 1099, 749);
		//contentPane = new JPanel();
		contentPane = this;
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		//setContentPane(contentPane);
		contentPane.setLayout(new GridLayout(1, 0, 0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		contentPane.add(tabbedPane);
		
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
		
		verTable = new JTable();
		String vColumnNames[] = { "Start", "Name", "Vulnerability", "Severity", "VulnId" };
		verModel = new VTTableModel(vColumnNames);
		verTable.setAutoCreateRowSorter(true);
		verTable.setModel(verModel);
		Vector vvect = new Vector();
		vvect.add("");vvect.add("");vvect.add("");vvect.add("");
		verModel.addRow(vvect);
		verTable.getRowSorter().toggleSortOrder(0);
		verTable.addMouseListener(new MouseAdapter(){
		    public void mouseClicked(MouseEvent evnt) {
		        if (evnt.getClickCount() == 1) {
			        synchronized(this){
			        	
			        	int r = verTable.getSelectedRow();
			        	int row = verTable.convertRowIndexToModel(r);
			        	
			        	Long vid = (Long)verModel.getValueAt(row, 4);
			        	JSONArray json = api.executeGet("/assessments/vuln/" + vid);
			        	JSONObject j = (JSONObject)json.get(0);
			        	JSONArray s = (JSONArray)j.get("Steps");
			        	List<String> Images = new ArrayList<String>();
			        	List<String> Steps = new ArrayList<String>();
			        	List<Integer>ImageIds = new ArrayList<Integer>();
			        	for(int i=0; i< s.size(); i++){
			        		JSONObject jObj = (JSONObject)s.get(i);
			        		Steps.add((String)jObj.get("Description"));
			        		Images.add((String)jObj.get("ScreenShot"));
			        		if(jObj.get("ImageId")!= null)
			        			ImageIds.add(((Long)jObj.get("ImageId")).intValue());
			        		
			        		
			        	}
			        	//com.fuse.data.Handler.install();
			        	ExploitStepsPanel test = new ExploitStepsPanel(api,(String)j.get("Name"), (String)j.get("Description"),(String)j.get("Recommendation"), Steps, Images, ImageIds, cb);
			        	test.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
			        	test.setSize(900, 1000);
			        	test.setVisible(true);
		        	}
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
		
		JButton updateVerBtn = new JButton("Update");
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
		String columnNames[] = { "AppId", "AppName", "Start Date", "EndDate" };
		asmtModel = new VTTableModel(columnNames);
		queueTable.setAutoCreateRowSorter(true);
		queueTable.setModel(asmtModel);
		Vector vect = new Vector();
		vect.add("");vect.add("");vect.add("");vect.add("");
		asmtModel.addRow(vect);
		queueTable.getRowSorter().toggleSortOrder(2);
		queueTable.addMouseListener(new MouseAdapter(){
		    public void mouseClicked(MouseEvent evnt) {
		        if (evnt.getClickCount() == 1) {
		        	synchronized(this){
			        	int r = queueTable.getSelectedRow();
			        	int row = queueTable.convertRowIndexToModel(r);
			        	
			        	for(int i = vulnModel.getRowCount()-1; i >=0; i--){
							vulnModel.removeRow(i);
							
						}
			        	appId = ""+asmtModel.getValueAt(row, 0);
			        	asmtName.setText("AppId: " + appId + " - " + asmtModel.getValueAt(row, 1) + " - Start: " + asmtModel.getValueAt(row, 2) + " - End: " + asmtModel.getValueAt(row, 3));
			        	asmtName.setEditable(false);
			        	String NotesStr = Notes.get(row) == null ? "" : ""+Notes.get(row);
			        	String [] notes = NotesStr.split("<!--Split-->");
			        	notesTxt.setText(notes[0]==null? "Nothing to Show" : notes[0]);
			        	if(notes.length==2)
			        		notes2Txt.setText(notes[1]==null? "Nothing to Show" : notes[1]);
			        	JSONArray json = new JSONArray();
						try {
							json = api.executeGet("/assessments/history/" + URLEncoder.encode(appId,"UTF-8"));
						} catch (UnsupportedEncodingException e) {
							// TODO Auto-generated catch block
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
		
		vulnModel = new VTTableModel(vcolnames);
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
		
		vulnTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer(){
		    @Override
		    public Component getTableCellRendererComponent(JTable table,
		            Object value, boolean isSelected, boolean hasFocus, int row, int col) {
		    	
		        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
		        int realRow = table.convertRowIndexToModel(row);
		        
		        String status = "" + table.getModel().getValueAt(realRow, col);
		        if ("Critical".equals(status)) {
		            setBackground(new Color(231, 76, 60));
		            setForeground(Color.WHITE);
		        } else if ("High".equals(status)) {
		            setBackground(new Color(230, 126, 34));
		            setForeground(Color.WHITE);
		        } else if ("Medium".equals(status)) {
		            setBackground(new Color(52, 152, 219));
		            setForeground(Color.WHITE);
		        } else {
		        	if(row%2==0){
			            setBackground(table.getBackground());  
		        	}else{
		        		setBackground(Color.getColor("EEEEEE"));
		        	}
		        	setForeground(table.getForeground());
		        }       
		        return this;
		    }   
		});
		vulnTable.addMouseListener(new MouseAdapter(){
		    public void mouseClicked(MouseEvent evnt) {
		        if (evnt.getClickCount() == 1) {
		        	synchronized(this){
			        	int r = vulnTable.getSelectedRow();
			        	int row = vulnTable.convertRowIndexToModel(r);
			        	Long vid = (Long)vulnModel.getValueAt(row, 6);
			        	JSONArray json = api.executeGet("/assessments/vuln/" + vid);
			        	JSONObject j = (JSONObject)json.get(0);
			        	JSONArray s = (JSONArray)j.get("Steps");
			        	List<String> Images = new ArrayList<String>();
			        	List<String> Steps = new ArrayList<String>();
			        	List<Integer>ImageIds = new ArrayList<Integer>();
			        	for(int i=0; i< s.size(); i++){
			        		JSONObject jObj = (JSONObject)s.get(i);
			        		Steps.add((String)jObj.get("Description"));
			        		Images.add((String)jObj.get("ScreenShot"));
			        		if(jObj.get("ImageId")!= null)
			        			ImageIds.add(((Long)jObj.get("ImageId")).intValue());
			        		
			        		
			        	}
			        	//com.fuse.data.Handler.install();
			        	ExploitStepsPanel test = new ExploitStepsPanel(api,(String)j.get("Name"), (String)j.get("Description"),(String)j.get("Recommendation"), Steps, Images, ImageIds, cb);
			        	test.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
			        	test.setSize(900, 1000);
			        	test.setVisible(true);
		        	}
		        	
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
		
		JButton updateBtn = new JButton("Update");
		updateBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				api.updateProps(serverTxt.getText(), tokenTxt.getText(), refreshRate.getText());
				try{
				refreshTimer.cancel();
				}catch(Exception ex){}
				refreshTimer = new Timer();
				refreshTimer.scheduleAtFixedRate(new TimerTask(){
					@Override
					public void run() {
						updateAPI();
						
					}}, 0, 1000 * api.getRefresh());
				

			}
		});
		updateBtn.setBounds(305, 129, 117, 25);
		ConfigPanel.add(updateBtn);
		
		serverTxt.setText(api.getServer());
		tokenTxt.setText(api.getToken());
		
		
		JLabel lblRefresh = new JLabel("Refresh:");
		lblRefresh.setBounds(32, 134, 46, 25);
		ConfigPanel.add(lblRefresh);
		
		refreshRate = new JTextField();
		refreshRate.setText("20");
		refreshRate.setBounds(88, 129, 46, 25);
		ConfigPanel.add(refreshRate);
		refreshRate.setColumns(10);
		refreshRate.setText("" + api.getRefresh());
		
		JLabel lblSecs = new JLabel("Seconds");
		lblSecs.setBounds(144, 134, 100, 20);
		ConfigPanel.add(lblSecs);
		
		
		refreshTimer = new Timer();
		refreshTimer.scheduleAtFixedRate(new TimerTask(){

			@Override
			public void run() {
				updateAPI();
				
			}}, 0, 1000 * api.getRefresh());
		
		
	}
	
	private synchronized void  updateAPI() {
		
		/*
		 * Get Verificaiton Queue
		 */
		JSONArray vjson = api.executeGet(FuseAPI.VQUEUE);
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
		JSONArray json = api.executeGet(FuseAPI.QUEUE);
		if(json == null)
			return;
		/*
		 * Update Assessment information.
		 */
		if(asmtModel.getRowCount() != json.size() || json.size() == 1 ){
			Notes.clear();
			for(int i = asmtModel.getRowCount()-1; i >=0; i--){
				asmtModel.removeRow(i);
				
			}
			
			
			for(int i = 0 ; i< json.size(); i++){
				JSONObject obj = (JSONObject)json.get(i);
				Vector vect = new Vector();
				vect.add(obj.get("AppId"));
				vect.add(obj.get("Name"));
				vect.add(convertDate((String)obj.get("Start")));
				vect.add(convertDate((String)obj.get("End")));
				asmtModel.addRow(vect);
				String creds = obj.get("AccessNotes") == null ? "" : (String)obj.get("AccessNotes");
				String notes = obj.get("Notes") == null ? "" : (String)obj.get("Notes");
				Notes.add(creds + "<!--Split-->" + notes);
				
			}
		}
		/*
		 * Add Only new findings to the table if an application is selected.
		 */
		if(!appId.equals("")){
			JSONArray vulns = new JSONArray();
			try {
				vulns = api.executeGet("/assessments/history/" + URLEncoder.encode(appId,"UTF-8"));
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
        			//System.out.println(vulnModel.getValueAt(j, 6) + " , " + v.get(6));
        			if((""+vulnModel.getValueAt(j, 6)).equals(""+v.get(6))){
        				found = true;
        				break;
        			}
        		}
        		
        		if(!found){
        			
					//InputStream is= this.getClass().getResourceAsStream("/com/fuse/gui/newvuln.wav");
					//playSoundInternal(is);
        			
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
    				//InputStream is=this.getClass().getResourceAsStream("/com/fuse/gui/delvuln.wav");
					//playSoundInternal(is);
    				vulnModel.removeRow(j);
    				
    			}
    		}
		}
		
	}
	
	
	public static String convertDate(String date){
		SimpleDateFormat sdf1 = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy");
		SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd");
		try {
			Date d = sdf1.parse(date);
			return sdf2.format(d);
		} catch (java.text.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
		
		
	}
	
	public String getAppId(){
		return this.appId;
	}
	private void playSoundInternal(InputStream f) {
	    try {
	    	
	        AudioInputStream audioInputStream = AudioSystem.getAudioInputStream(f);
	        try {
	            Clip clip = AudioSystem.getClip();
	            clip.open(audioInputStream);
	            try {
	                clip.start();
	                try {
	                    Thread.sleep(100);
	                } catch (InterruptedException e) {
	                    e.printStackTrace();
	                }
	                clip.drain();
	            } finally {
	                clip.close();
	            }
	        } catch (LineUnavailableException e) {
	            e.printStackTrace();
	        } finally {
	            audioInputStream.close();
	        }
	    } catch (UnsupportedAudioFileException e) {
	        e.printStackTrace();
	    } catch (FileNotFoundException e) {
	        e.printStackTrace();
	    } catch (IOException e) {
	        e.printStackTrace();
	    }
	}
	
	 public static void tone(float hz, int msecs, double vol){
		 try {
		    byte[] buf = new byte[1];
		    AudioFormat af = 
		        new AudioFormat(
		        	8000f, // sampleRate
		            8,           // sampleSizeInBits
		            1,           // channels
		            true,        // signed
		            false);      // bigEndian
		    SourceDataLine sdl;
			
			sdl = AudioSystem.getSourceDataLine(af);
			
		    sdl.open(af);
		    sdl.start();
		    for (int i=0; i < msecs*8; i++) {
		      double angle = i / (8000f / hz) * 2.0 * Math.PI;
		      buf[0] = (byte)(Math.sin(angle) * 127.0 * vol);
		      sdl.write(buf,0,1);
		    }
		    sdl.drain();
		    sdl.stop();
		    sdl.close();
			} catch (LineUnavailableException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		  }
}
