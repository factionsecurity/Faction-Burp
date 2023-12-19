package com.org.faction.api;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class FactionAPI {
	
	private String SERVER ="";
	private String TOKEN = "";
	private Integer refresh;
	private LinkedHashMap<String, Integer> levelMap = new LinkedHashMap();
	private int highSev=4;
	private int medSev=3;
	private int lowSev=2;
	private int infoSev=0;
	public static final String ADDVULN="/assessments/addVuln/";
	public static final String ADDDEFAULTVULN="/assessments/addDefaultVuln/";
	public static final String SEARCH_DEFAULT_VULN="/vulnerabilities/default/";
	public static final String QUEUE="/assessments/queue";
	public static final String VQUEUE="/verifications/queue";
	public static final String GETVULN="/assessments/vuln/";
	public static final String GETVULNS="/assessments/vulns/";
	public static final String SETNOTE="/assessments/notes/";
	public static final String HISTORY="/assessments/history/";
	public static final String LEVELS="/vulnerabilities/getrisklevels/";

	public static final String BURP_SEV_HIGH="high";
	public static final String BURP_SEV_MED="medium";
	public static final String BURP_SEV_LOW="low";
	public static final String BURP_SEV_INFO="information";
	
	
	
	public FactionAPI(){
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
		switch (burpSeverityString.toLowerCase()) {
			case "high":
				return this.highSev;	
			case "medium":
				return this.medSev;
			case "low":
				return this.lowSev;
			case "information":
				return this.infoSev;
			default:
				return this.infoSev;
		}
	}

	public String [] getSeverityStrings(){
		this.getLevelMap();
		List<String> strings = new ArrayList<>();
		for(Map.Entry<String,Integer> entry : levelMap.entrySet()){
			strings.add(entry.getKey());
		}
		return strings.toArray(new String[0]);
	}

	public String getSeverityStringFromSeverityId(Integer sevId){
		for(Map.Entry<String, Integer> entry : levelMap.entrySet()){
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
	public void updateSev(String burpSevName, String sevName){
		Integer sevId = this.levelMap.get(sevName);
		Properties props = this.getProps();
		String path = System.getProperty("user.home") + File.separator +"/.faction" + File.separator;
        File f = new File(path + "faction.properties");
		OutputStream out;
		try {
			props.setProperty(burpSevName, ""+sevId);
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
			this.highSev = Integer.parseInt(props.getProperty(BURP_SEV_HIGH, "4"));
			this.medSev = Integer.parseInt(props.getProperty(BURP_SEV_MED, "3"));
			this.lowSev = Integer.parseInt(props.getProperty(BURP_SEV_LOW, "2"));
			this.infoSev = Integer.parseInt(props.getProperty(BURP_SEV_INFO, "0"));
			return props;
	    }
	    catch ( Exception e ) { is = null; }
		return null;
	 
	 
	}

	public LinkedHashMap<String, Integer> getLevelMap(){
		JSONArray array = this.executeGet(LEVELS);
		
		for(int i=0; i< array.size(); i++){
			JSONObject obj = (JSONObject)array.get(i);
			if(obj.get("name") == null || (""+obj.get("name")).equals(""))
				continue;
			levelMap.put((""+obj.get("name")).toLowerCase(), ((Long)obj.get("id")).intValue());
		}
		return levelMap;

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
	
	public String getCSS(){
		return SERVER.replace("api", "") + "service/rd_styles.css";
	}

}
