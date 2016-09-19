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
import java.util.Properties;

import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class FuseAPI {
	
	private String SERVER ="";
	private String TOKEN = "";
	private Integer refresh;
	public static String ADDVULN="/assessments/addVuln/";
	public static String QUEUE="/assessments/queue";
	public static String GETVULN="/assessments/vuln/";
	public static String GETVULNS="/assessments/vulns/";
	public static String SETNOTE="/assessments/notes/";
	public static String HISTORY="/assessments/history/";
	
	
	
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
	public void updateProps(String Server, String Token, String Refresh){
		this.SERVER = Server;
		this.TOKEN = Token;
		this.refresh = Integer.parseInt(Refresh);
		Properties props = new Properties();
		props.setProperty("server", Server);
		props.setProperty("token", Token);
		props.setProperty("refresh", Refresh);
		File f = new File("faction.properties");
		OutputStream out;
		try {
			out = new FileOutputStream( f );
			props.store(out, "Saved by Faction");
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void getProps(){
		Properties props = new Properties();
	    InputStream is = null;
	 
	    try {
	        File f = new File("faction.properties");
	        if(!f.exists())
	        	f.createNewFile();
	        is = new FileInputStream( f );
	        props.load(is);
	        this.SERVER = props.getProperty("server", "");
	        this.TOKEN = props.getProperty("token","");
	        this.refresh = Integer.parseInt(props.getProperty("refresh","20"));
	        
	    }
	    catch ( Exception e ) { is = null; }
	 
	 
	}
	public JSONArray executePost(String targetURL, String postData){
		HttpURLConnection connection = null;  
		  try {
		    //Create connection
		    URL url = new URL(this.SERVER + targetURL);
		    connection = (HttpURLConnection)url.openConnection();
		    connection.setRequestMethod("POST");

		    connection.setRequestProperty("VTRK-API-KEY", this.TOKEN);
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
		    URL url = new URL(this.SERVER + targetURL);
		    connection = (HttpURLConnection)url.openConnection();
		    connection.setRequestMethod("GET");

		    connection.setRequestProperty("VTRK-API-KEY", this.TOKEN);
		    connection.setRequestProperty("Content-Language", "en-US");  
		    connection.setRequestProperty("Accept", "application/json");

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
	
	public static int setSeverity(String severity){
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

}
