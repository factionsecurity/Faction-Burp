package com.org.faction.utils;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.function.Consumer;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;

import org.apache.commons.lang.StringEscapeUtils;

import com.org.faction.api.FactionAPI;
import com.sun.jersey.core.util.Base64;

import burp.IHttpRequestResponse;

public class FSUtils {

	 

	public static void setSeverityComboBoxDefaults(FactionAPI api, JComboBox jbox, String burpSeverityString, String [] severityStrings, Consumer<String> callback){	
		jbox.setModel(new DefaultComboBoxModel(severityStrings));
		int sevId = api.getSevMapping(burpSeverityString);
		String sevStr = api.getSeverityStringFromSeverityId(sevId);
		for(int j =0; j<jbox.getItemCount(); j++){
			if(jbox.getItemAt(j).equals(sevStr)){
				jbox.setSelectedIndex(j);
				break;
			}
		}
		jbox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String selectedSev = jbox.getSelectedItem().toString();
				callback.accept(selectedSev);
				//api.updateSev(burpSeverityString, selectedSev);
			}
		});
	}
	
	public static Boolean ask(String question, Scanner reader){
		String answer = "";
		System.out.println(question);
	
		while(true){
			System.out.println("[y]es | [n]o | [e]xit");
			answer= reader.next();
			if(answer.startsWith("y") || answer.startsWith("n") || answer.startsWith("e"))
				break;
			if(answer.startsWith("Y") || answer.startsWith("N") || answer.startsWith("E"))
				break;
		}
		if(answer.startsWith("e") || answer.startsWith("E")){
			System.out.println("Cancelling Import.");
			return null;
		}else if(answer.startsWith("n") || answer.startsWith("N")){
			return false;
		}else if(answer.startsWith("y") || answer.startsWith("Y")){
			return true;
		}
		System.out.println("An Error Occured");
		return null;
	}
	public static String createMessage(String Message, String Req, String Resp, boolean snipCookies, boolean encode){
		String message = createMessage(Message, Req,Resp, snipCookies);
		if(encode)
			message=new String(Base64.encode(message));
		try {
			message=URLEncoder.encode(message, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return message;
	}
	
	private static String createMessage(String Message, String Req, String Resp, boolean snipCookies){
		String message = Message;
		message = message.replace("\r\n", "<br />").replace("\n", "<br />");
		if(Req!= null && !Req.equals("")){
			message += "<b>Request: </b>";
			message += "<div class='code' style='background:#eee;border:1px solid #ccc;padding:5px 10px;'>";
			message += "<pre class='code'>";
			
			String tmp = Req;
			if(snipCookies){
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
		if(Resp != null && !Resp.equals("")){
			message += "<b>Response: </b>";
			message += "<div class='code' style='background:#eee;border:1px solid #ccc;padding:5px 10px;'>";
			message += "<pre class='code'>";
			
			String tmp = Resp;
			if(snipCookies){
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
			data = data.replace("[ ...snip... ]", "<b>[ ...snip... ]</b>");
			message += data;
			message += "</pre></div>";
			
		}
		return message;
	}
	public static String hashText(String text){
		try {
			MessageDigest md;
			md = MessageDigest.getInstance("MD5");
			md.update(text.getBytes());
			byte[] digest = md.digest();
			return new String(digest, StandardCharsets.UTF_8);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return "";

	}
	


}
