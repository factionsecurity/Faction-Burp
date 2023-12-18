package com.fuse.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Scanner;

import org.apache.commons.lang.StringEscapeUtils;

import com.sun.jersey.core.util.Base64;

import burp.IHttpRequestResponse;

public class FSUtils {
	
	public static int setSeverity(String severity){
		if(severity.equals("Informational"))
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
			return 4;
		else 
			return 0;
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


}
