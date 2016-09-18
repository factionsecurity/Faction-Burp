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
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.swing.JTextArea;
import javax.swing.Box;

import java.awt.Dimension;
import java.awt.Font;

import javax.swing.border.TitledBorder;
import javax.swing.border.LineBorder;
import javax.swing.JPasswordField;

public class FactionGUI extends JPanel  {

	private JPanel contentPane;
	private JTextField serverTxt;
	private JPasswordField tokenTxt;
	private JTable queueTable;
	private VTTableModel asmtModel;
	private VTTableModel vulnModel;
	private JTable vulnTable;
	private JTextField asmtName;
	private JEditorPane notesTxt;
	private List<String> Notes = new ArrayList<String>();
	private FuseAPI api = new FuseAPI();
	private JTextField refreshRate;
	private Timer refreshTimer;



	/**
	 * Create the frame.
	 */
	public FactionGUI() {
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
		
		JPanel queuePanel = new JPanel();
		tabbedPane.addTab("Queue", null, queuePanel, null);
		GridBagLayout gbl_queuePanel = new GridBagLayout();
		gbl_queuePanel.columnWidths = new int[]{0, 0};
		gbl_queuePanel.rowHeights = new int[]{644, 0, 0};
		gbl_queuePanel.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_queuePanel.rowWeights = new double[]{1.0, 0.0, Double.MIN_VALUE};
		queuePanel.setLayout(gbl_queuePanel);
		
		JScrollPane scrollPane = new JScrollPane();
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 0;
		queuePanel.add(scrollPane, gbc_scrollPane);
		
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
		        	int r = queueTable.getSelectedRow();
		        	int row = queueTable.convertRowIndexToModel(r);
		        	
		        	for(int i = vulnModel.getRowCount()-1; i >=0; i--){
						vulnModel.removeRow(i);
						
					}
		        	Long appId = (Long)asmtModel.getValueAt(row, 0);
		        	asmtName.setText("AppId: " + appId + " - " + asmtModel.getValueAt(row, 1) + " - Start: " + asmtModel.getValueAt(row, 2) + " - End: " + asmtModel.getValueAt(row, 3));
		        	asmtName.setEditable(false);
		        	notesTxt.setText(Notes.get(r));
		        	JSONArray json = api.executeGet("/assessments/history/" + appId);
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
		
		scrollPane.setViewportView(queueTable);
		
		JPanel panel = new JPanel();
		GridBagConstraints gbc_panel = new GridBagConstraints();
		gbc_panel.anchor = GridBagConstraints.SOUTH;
		gbc_panel.fill = GridBagConstraints.HORIZONTAL;
		gbc_panel.gridx = 0;
		gbc_panel.gridy = 1;
		queuePanel.add(panel, gbc_panel);
		panel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JButton btnNewButton = new JButton("Update");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				updateAPI();

			}
		});
		panel.add(btnNewButton);
		
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
		panel_2.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)), "Assessment Notes/Credentials", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(51, 51, 51)));
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
		
		notesTxt = new JEditorPane();
		GridBagConstraints gbc_notesTxt = new GridBagConstraints();
		gbc_notesTxt.fill = GridBagConstraints.BOTH;
		gbc_notesTxt.gridx = 0;
		gbc_notesTxt.gridy = 0;
		panel_2.add(notesTxt, gbc_notesTxt);
		notesTxt.setEditable(false);
		notesTxt.setContentType("text/html");
		
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
		        	ExploitStepsPanel test = new ExploitStepsPanel((String)j.get("Name"), (String)j.get("Description"),(String)j.get("Recommendation"), Steps, Images, ImageIds);
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
		
		JButton updateBtn = new JButton("Update");
		updateBtn.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				api.updateProps(serverTxt.getText(), tokenTxt.getText(), refreshRate.getText());
				refreshTimer.cancel();
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
	
	private void updateAPI(){
		
		
		JSONArray json = api.executeGet(FuseAPI.QUEUE);
		if(json == null)
			return;
		if(asmtModel.getRowCount() != json.size()){
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
				Notes.add((String)obj.get("AccessNotes") + "<hr>" + (String)obj.get("Notes"));
				
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
}
