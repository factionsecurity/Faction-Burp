package com.faction.api;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;

public class FactionAPI {

	private String SERVER = "";
	private String TOKEN = "";
	private String PORT = "8090"; // Initialiser PORT avec une chaîne
// Valeur par défaut pour HTTP, 443 pour HTTPS par exemple
	private Integer refresh;
	private LinkedHashMap<String, Integer> levelMap = new LinkedHashMap();
	private int highSev = 4;
	private int medSev = 3;
	private int lowSev = 2;
	private int infoSev = 0;
	public static final String ADDVULN = "/api/assessments/addVuln/";
	public static final String ADDDEFAULTVULN = "/api/assessments/addDefaultVuln/";
	public static final String SEARCH_DEFAULT_VULN = "/api/vulnerabilities/default/";
	public static final String QUEUE = "/api/assessments/queue";
	public static final String VQUEUE = "/api/verifications/queue";
	public static final String GETVULN = "/api/assessments/vuln/";
	public static final String GETVULNS = "/api/assessments/vulns/";
	public static final String SETNOTE = "/api/assessments/notes/";
	public static final String HISTORY = "/api/assessments/history/";
	public static final String LEVELS = "/api/vulnerabilities/getrisklevels/";

	public static final String BURP_SEV_HIGH = "high";
	public static final String BURP_SEV_MED = "medium";
	public static final String BURP_SEV_LOW = "low";
	public static final String BURP_SEV_INFO = "information";

	private Http http;
	private Logging logging;

	public FactionAPI(MontoyaApi api) {
		getProps();
		http = api.http();
		logging = api.logging();

	}

	public String getServer() {
		return this.SERVER;
	}

	public String getToken() {
		return this.TOKEN;
	}

	public int getRefresh() {
		return refresh;
	}

	public Integer getSevMapping(String burpSeverityString) {
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

	public String[] getSeverityStrings() {
		this.getLevelMap();
		List<String> strings = new ArrayList<>();
		for (Map.Entry<String, Integer> entry : levelMap.entrySet()) {
			strings.add(entry.getKey());
		}
		return strings.toArray(new String[0]);
	}

	public String getSeverityStringFromSeverityId(Integer sevId) {
		for (Map.Entry<String, Integer> entry : levelMap.entrySet()) {
			if (entry.getValue().equals(sevId)) {
				return entry.getKey();
			}
		}
		return null;
	}

	public void updateProps(String server, String token, String refresh) {
		this.SERVER = server;
		this.TOKEN = token;
		this.PORT = PORT;
		this.refresh = Integer.parseInt(refresh);
		Properties props = this.getProps();
		props.setProperty("server", server);
		props.setProperty("token", token);
		props.setProperty("port", PORT);
		props.setProperty("refresh", refresh);
		String path = System.getProperty("user.home") + File.separator + "/.faction" + File.separator;
		File f = new File(path + "faction.properties");
		OutputStream out;
		try {
			out = new FileOutputStream(f);
			props.store(out, "Saved by Faction");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void updateSev(String burpSevName, String sevName) {
		Integer sevId = this.levelMap.get(sevName);
		Properties props = this.getProps();
		String path = System.getProperty("user.home") + File.separator + "/.faction" + File.separator;
		File f = new File(path + "faction.properties");
		OutputStream out;
		try {
			props.setProperty(burpSevName, "" + sevId);
			out = new FileOutputStream(f);
			props.store(out, "Saved by Faction");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public Properties getProps() {
		Properties props = new Properties();
		InputStream is = null;
	
		try {
			String path = System.getProperty("user.home") + File.separator + "/.faction" + File.separator;
			File f = new File(path + "faction.properties");
	
			if (!f.exists()) {
				File p = new File(path);
				if (!p.exists()) {
					p.mkdir();
				}
				f.createNewFile();
			}
			is = new FileInputStream(f);
			props.load(is);
			this.SERVER = props.getProperty("server", "");
			this.TOKEN = props.getProperty("token", "");
			this.PORT = props.getProperty("port", "8090"); // Chargement du port
			this.refresh = Integer.parseInt(props.getProperty("refresh", "20"));
			this.highSev = Integer.parseInt(props.getProperty(BURP_SEV_HIGH, "4"));
			this.medSev = Integer.parseInt(props.getProperty(BURP_SEV_MED, "3"));
			this.lowSev = Integer.parseInt(props.getProperty(BURP_SEV_LOW, "2"));
			this.infoSev = Integer.parseInt(props.getProperty(BURP_SEV_INFO, "0"));
			// ... le reste de la méthode ...
			return props;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	

	public LinkedHashMap<String, Integer> getLevelMap() {
		JSONArray array = this.executeGet(LEVELS);


		for (int i = 0; i < array.size(); i++) {
			JSONObject obj = (JSONObject) array.get(i);
			if (obj.get("name") == null || ("" + obj.get("name")).equals(""))
				continue;
			levelMap.put(("" + obj.get("name")).toLowerCase(), ((Long) obj.get("id")).intValue());
		}
		return levelMap;

	}

	public JSONArray executePost(String targetURL, String postData) {
		try {
			logging.logToOutput("Sending Post");
			URL url = new URL(this.SERVER + ":" + this.PORT + targetURL); // Assurez-vous que l'URL est correcte
			logging.logToOutput("URL: " + url.toString()); // Journaliser l'URL complète
			String targetHost = url.getHost();
			int portInt = Integer.parseInt(this.PORT);
			boolean isSecure = url.getProtocol().equals("https");
			HttpService service = HttpService.httpService(targetHost, portInt, isSecure);
	
			HttpRequest request = HttpRequest
					.httpRequest()
					.withService(service)
					.withHeader("Host", targetHost)
					.withMethod("POST")
					.withPath(targetURL)
					.withAddedHeader("FACTION-API-KEY", this.TOKEN)
					.withAddedHeader("Content-Language", "en-US")
					.withAddedHeader("Accept", "application/json")
					.withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
					.withBody(postData);
	
			// Journaliser les détails de la requête
			logging.logToOutput("Request Headers: " + request.headers().toString());
			logging.logToOutput("Request Body: " + postData);
	
			CompletableFuture<HttpRequestResponse> requestResponse = CompletableFuture.supplyAsync(() -> {
				HttpRequestResponse response = http.sendRequest(request);
				return response;
			});
	
			HttpRequestResponse response = requestResponse.get();
			logging.logToOutput("Sending request to: " + url.toString());
			logging.logToOutput("Request Method: " + request.method().toString());
			logging.logToOutput("Request Headers: " + request.headers().toString());
			if (request.method().equals("POST")) {
				logging.logToOutput("Request Body: " + postData); // Pour les requêtes POST uniquement
			}
			if (response != null && response.hasResponse()) {
				logging.logToOutput("Received response with status code: " + response.response().statusCode());
			
				// Imprimer les en-têtes de réponse
				logging.logToOutput("Response Headers: " + response.response().headers().toString());
			
				// Imprimer le corps de la réponse, s'il est présent
				if (response.response().body() != null) {
					logging.logToOutput("Response Body: " + response.response().bodyToString());
				}
			} else {
				logging.logToOutput("No response received.");
			}
			
			if (response.hasResponse() && response.response().statusCode() == 200) {
				String jsonString = response.response().bodyToString();

				JSONParser parser = new JSONParser();
				try {
					JSONArray json = (JSONArray) parser.parse(jsonString);
					return json;
				} catch (ParseException e1) {
					e1.printStackTrace();
					logging.logToError(e1.getMessage());
					return new JSONArray();
				}
			}else{
				logging.logToError("No Response From Faction");
				return new JSONArray();
			}
		} catch (Exception e) {
			e.printStackTrace();
			logging.logToError(e.getMessage());
			return new JSONArray();
		}
	}

	public JSONArray executeGet(String targetURL) {
		try {
			URL url = new URL(this.SERVER + ":" + this.PORT + targetURL); // Assurez-vous que l'URL est correcte
			logging.logToOutput("URL: " + url.toString()); // Journaliser l'URL complète
			String targetHost = url.getHost();
			int portInt = Integer.parseInt(this.PORT);
			boolean isSecure = url.getProtocol().equals("https");
			HttpService service = HttpService.httpService(targetHost, portInt, isSecure);
	
			HttpRequest request = HttpRequest
					.httpRequest()
					.withService(service)
					.withHeader("Host", targetHost)
					.withMethod("GET")
					.withPath(targetURL.replace("+", "%20"))
					.withAddedHeader("FACTION-API-KEY", this.TOKEN)
					.withAddedHeader("Content-Language", "en-US")
					.withAddedHeader("Accept", "application/json");
	
			// Journaliser les détails de la requête
			logging.logToOutput("Request Headers: " + request.headers().toString());
	
			CompletableFuture<HttpRequestResponse> requestResponse = CompletableFuture.supplyAsync(() -> {
				HttpRequestResponse response = http.sendRequest(request);
				return response;
			});
			logging.logToOutput("Sending request to: " + url.toString());
			logging.logToOutput("Request Method: " + request.method().toString());
			logging.logToOutput("Request Headers: " + request.headers().toString());

			
			HttpRequestResponse response = requestResponse.get();
			if (response != null && response.hasResponse()) {
				logging.logToOutput("Received response with status code: " + response.response().statusCode());
			
				// Imprimer les en-têtes de réponse
				logging.logToOutput("Response Headers: " + response.response().headers().toString());
			
				// Imprimer le corps de la réponse, s'il est présent
				if (response.response().body() != null) {
					logging.logToOutput("Response Body: " + response.response().bodyToString());
				}
			} else {
				logging.logToOutput("No response received.");
			}
			if (response.hasResponse() && response.response().statusCode() == 200) {
				JSONParser parser = new JSONParser();
				try {
					JSONArray json = (JSONArray) parser.parse(response.response().bodyToString());
					return json;
				} catch (ParseException e1) {
					e1.printStackTrace();
					logging.logToError(e1.getMessage());
				}
			}
			logging.logToError("No Response From Faction");
			return new JSONArray();
		} catch (Exception e) {
			e.printStackTrace();
			logging.logToError(e.getMessage());
			return new JSONArray();
		}
	}

	public String getCSS() {
		// Cette version suppose que SERVER inclut le protocole, l'hôte et le port si nécessaire.
		// Elle ajoute simplement le chemin approprié au fichier CSS, sans tenter de remplacer ou d'ajuster "api".
		return SERVER + "/service/rd_styles.css";
	}
	

}
