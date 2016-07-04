package com.fuse.cli.burp;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.fuse.api.FuseAPI;
import com.fuse.utils.FSUtils;
import com.sun.jersey.core.util.Base64;

public class BurpImporter {
	
	
	public static void importXML(File xml){
		try{
			Scanner reader = new Scanner(System.in);
			FuseAPI api = new FuseAPI();
			JSONArray apps = api.executeGet(FuseAPI.QUEUE);
			System.out.println("Select an Application: ");
			for(int i=0; i<apps.size(); i++){
				JSONObject app = (JSONObject)apps.get(i);
				System.out.println("" + i +": " + app.get("AppId") + " " + app.get("Name"));
			}
			int selected = reader.nextInt();
			String appid = ""+((JSONObject)apps.get(selected)).get("Id");
			
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(xml);
					
			doc.getDocumentElement().normalize();
	
			NodeList nList = doc.getElementsByTagName("issue");
			int size = nList.getLength();
			
			for(int i =0; i< nList.getLength(); i++){
				Node node = nList.item(i);
				Element issue = (Element) node;
				String name = issue.getElementsByTagName("name").item(0).getTextContent();
				String severity = issue.getElementsByTagName("severity").item(0).getTextContent();
				String host = issue.getElementsByTagName("host").item(0).getTextContent();
				Element reqRes = (Element)issue.getElementsByTagName("requestresponse").item(0);
				
				String req = "";
				String resp = "";
				if(reqRes !=null && reqRes.getElementsByTagName("request") != null){
					String b64req = reqRes.getElementsByTagName("request").item(0).getTextContent();
					req = new String(Base64.decode(b64req.getBytes()));
				}
				if(reqRes != null && reqRes.getElementsByTagName("response") != null){
					String b64resp = reqRes.getElementsByTagName("response").item(0).getTextContent();
					resp = new String(Base64.decode(b64resp.getBytes()));
				}
				Boolean ans = FSUtils.ask("Do you want to Import '" + name + "' ?", reader);
				if(ans == null)
					return;
				else if(!ans){
					//do nothing
					
				}else{
				
					Boolean doReq = FSUtils.ask("Include Request?", reader);
					Boolean doResp = FSUtils.ask("Include Response?", reader);
					Boolean doSnip = FSUtils.ask("Snip Cookies?", reader);
					if(!doReq)
						req=null;
					if(!doResp)
						resp=null;
					

					String postData="name=" + name + "&severity=" + FSUtils.setSeverity(severity) + 
							"&message=" + FSUtils.createMessage("", req, resp, doSnip, true);
					api.executePost(FuseAPI.ADDVULN + appid, postData);
				}
					
				
				
				
			}
		} catch (ParserConfigurationException | SAXException | IOException e) {
			
			e.printStackTrace();
		}finally{}
	}
	

	private static void exit(int i) {
		// TODO Auto-generated method stub
		
	}

}
