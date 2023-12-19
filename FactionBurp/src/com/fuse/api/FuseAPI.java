package com.fuse.api;

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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class FuseAPI {
	
	private String SERVER ="";
	private String TOKEN = "";
	private Integer refresh;
	private Map<String, Integer> levels = new HashMap();
	private int highSev=4;
	private int medSev=3;
	private int lowSev=2;
	private int infoSev=0;
	public static String ADDVULN="/assessments/addVuln/";
	public static String ADDDEFAULTVULN="/assessments/addDefaultVuln/";
	public static String SEARCH_DEFAULT_VULN="/vulnerabilities/default/";
	public static String QUEUE="/assessments/queue";
	public static String VQUEUE="/verifications/queue";
	public static String GETVULN="/assessments/vuln/";
	public static String GETVULNS="/assessments/vulns/";
	public static String SETNOTE="/assessments/notes/";
	public static String HISTORY="/assessments/history/";
	public static String LEVELS="/vulnerabilities/getrisklevels/";
	
	
	
	public FuseAPI(){
		getProps();
		
	}
	public String getServer(){
		return this.SERVER;
	}
	public String getToken(){
		return this.TOKEN;
	}
	public int getRefresh(){
		return refresh;
	}

	public Integer getSevMapping(String burpSeverityString){
		switch (burpSeverityString) {
			case "high":
				return this.highSev;	
			case "med":
				return this.medSev;
			case "low":
				return this.lowSev;
			case "info":
				return this.infoSev;
			default:
				return this.infoSev;
		}
	}

	public String [] getSeverityStrings(){
		this.getLevels();
		List<String> strings = new ArrayList<>();
		for(Map.Entry<String,Integer> entry : levels.entrySet()){
			strings.add(entry.getKey());
		}
		return strings.toArray(new String[0]);
	}

	public String getSeverityStringFromSeverityId(Integer sevId){
		for(Map.Entry<String, Integer> entry : levels.entrySet()){
			if(entry.getValue().equals(sevId)){
				return entry.getKey();
			}
		}
		return null;
	}
	public void updateProps(String server, String token, String refresh){
		this.SERVER = server;
		this.TOKEN = token;
		this.refresh = Integer.parseInt(refresh);
		Properties props = this.getProps();
		props.setProperty("server", server);
		props.setProperty("token", token);
		props.setProperty("refresh", refresh);
		String path = System.getProperty("user.home") + File.separator +"/.faction" + File.separator;
        File f = new File(path + "faction.properties");
		OutputStream out;
		try {
			out = new FileOutputStream( f );
			props.store(out, "Saved by Faction");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public void updateSev(String sevName, int sevId){
		Properties props = this.getProps();
		String path = System.getProperty("user.home") + File.separator +"/.faction" + File.separator;
        File f = new File(path + "faction.properties");
		OutputStream out;
		try {
			props.setProperty(sevName, ""+sevId);
			out = new FileOutputStream( f );
			props.store(out, "Saved by Faction");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public Properties getProps(){
		Properties props = new Properties();
	    InputStream is = null;
	 
	    try {
	    	String path = System.getProperty("user.home") + File.separator +"/.faction" + File.separator;
	        File f = new File(path + "faction.properties");
	        
	        if(!f.exists()) {
	        	File p = new File(path);
	        	if(!p.exists()) {
	        		p.mkdir();
	        	}
	        	f.createNewFile();
	        }
	        is = new FileInputStream( f );
	        props.load(is);
	        this.SERVER = props.getProperty("server", "");
	        this.TOKEN = props.getProperty("token","");
	        this.refresh = Integer.parseInt(props.getProperty("refresh","20"));
			this.highSev = Integer.parseInt(props.getProperty("high", "4"));
			this.medSev = Integer.parseInt(props.getProperty("med", "3"));
			this.lowSev = Integer.parseInt(props.getProperty("low", "2"));
			this.infoSev = Integer.parseInt(props.getProperty("info", "0"));
			return props;
	    }
	    catch ( Exception e ) { is = null; }
		return null;
	 
	 
	}

	public Map<String, Integer> getLevels(){
		JSONArray array = this.executeGet(LEVELS);
		
		for(int i=0; i< array.size(); i++){
			JSONObject obj = (JSONObject)array.get(i);
			if((""+obj.get("name")).equals(""))
				continue;
			levels.put((""+obj.get("name")).toLowerCase(), ((Long)obj.get("id")).intValue());
		}
		return levels;

	}

	public JSONArray executePost(String targetURL, String postData){
		HttpURLConnection connection = null;  
		  try {
		    //Create connection
		    URL url = new URL(this.SERVER + targetURL);
		    connection = (HttpURLConnection)url.openConnection();
		    connection.setRequestMethod("POST");

		    connection.setRequestProperty("FACTION-API-KEY", this.TOKEN);
		    connection.setRequestProperty("Content-Language", "en-US");  
		    connection.setRequestProperty("Accept", "application/json");
		    connection.setRequestProperty("Content-Type", 
	                "application/x-www-form-urlencoded");
	             
		    connection.setDoOutput(true);

			DataOutputStream wr = new DataOutputStream (
			          connection.getOutputStream ());
			
			wr.writeBytes(postData);
			wr.flush ();
			wr.close ();
			connection.connect();

		    //Get Response  
			InputStream is = connection.getInputStream();
		    BufferedReader rd = new BufferedReader(new InputStreamReader(is));
		    StringBuilder response = new StringBuilder(); // or StringBuffer if not Java 5+ 
		    String line;
		    while((line = rd.readLine()) != null) {
		      response.append(line);
		      response.append('\r');
		    }
		    rd.close();
		    
		    JSONParser parser = new JSONParser();
			try {
				JSONArray json = (JSONArray) parser.parse(response.toString());
				
				return json;
			} catch (ParseException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		    return null;
		  } catch (Exception e) {
		    e.printStackTrace();
		    return null;
		  } finally {
		    if(connection != null) {
		      connection.disconnect(); 
		    }
		  }
	}
	
	public  JSONArray executeGet(String targetURL) {
		  HttpURLConnection connection = null;  
		  try {
		    //Create connection
		    URL url = new URL(this.SERVER + targetURL.replace("+", "%20"));
		    connection = (HttpURLConnection)url.openConnection();
		    connection.setRequestMethod("GET");

		    connection.setRequestProperty("FACTION-API-KEY", this.TOKEN);
		    connection.setRequestProperty("Content-Language", "en-US");  
		    connection.setRequestProperty("Accept", "application/json");

		    connection.connect();
			int statusCode = connection.getResponseCode();
			if(statusCode == 200){
				//Get Response  
				InputStream is = connection.getInputStream();
				BufferedReader rd = new BufferedReader(new InputStreamReader(is));
				StringBuilder response = new StringBuilder(); // or StringBuffer if not Java 5+ 
				String line;
				while((line = rd.readLine()) != null) {
				response.append(line);
				response.append('\r');
				}
				rd.close();
				
				JSONParser parser = new JSONParser();
				try {
					JSONArray json = (JSONArray) parser.parse(response.toString());
					
					return json;
				} catch (ParseException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		    return null;
		  } catch (Exception e) {
		    e.printStackTrace();
		    return null;
		  } finally {
		    if(connection != null) {
		      connection.disconnect(); 
		    }
		  }
		}
	
	public static int setSeverity2(String severity){
		
		if(severity.equals("Informational"))
			return 0;
		else if(severity.equals("Information"))
			return 0;
		else if(severity.equals("Recommended"))
			return 1;
		else if(severity.equals("Low"))
			return 2;
		else if(severity.equals("Medium"))
			return 3;
		else if(severity.equals("High"))
			return 4;
		else if(severity.equals("Critical"))
			return 5;
		else 
			return 0;
	}
	
	public String getCSS(){
		return SERVER.replace("api", "") + "service/rd_styles.css";
	}

}
