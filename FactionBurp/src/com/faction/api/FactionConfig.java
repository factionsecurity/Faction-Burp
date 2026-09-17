package com.faction.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * The extension's persisted settings: which Faction API generation to talk to,
 * where the server is, the API key, the queue refresh interval, and the
 * Burp→Faction severity mapping.
 *
 * Stored in {@code ~/.faction/faction.properties} — the same file the original
 * 1.x extension used, so existing installs keep their server, token and
 * mapping. Severity values are stored as Faction severity names; a 1.x install
 * may still hold the numeric risk-level ids the old extension wrote, and those
 * are handed back untouched for the v1 client to resolve.
 */
public final class FactionConfig {

	public static final String BURP_SEV_HIGH = "high";
	public static final String BURP_SEV_MED = "medium";
	public static final String BURP_SEV_LOW = "low";
	public static final String BURP_SEV_INFO = "information";

	public static final int DEFAULT_REFRESH = 20;
	public static final int DEFAULT_API_VERSION = 2;

	private static final String KEY_VERSION = "apiVersion";
	private static final String KEY_SERVER = "server";
	private static final String KEY_TOKEN = "token";
	private static final String KEY_REFRESH = "refresh";

	private final Path file;
	private final Properties props = new Properties();

	public FactionConfig(Path file) {
		this.file = file;
		reload();
	}

	/** {@code ~/.faction/faction.properties}. */
	public static FactionConfig defaultLocation() {
		return new FactionConfig(Paths.get(System.getProperty("user.home"), ".faction", "faction.properties"));
	}

	public Path file() {
		return file;
	}

	/** Re-reads the file; a missing or unreadable file yields defaults. */
	public synchronized void reload() {
		props.clear();
		if (!Files.exists(file)) return;
		try (InputStream in = Files.newInputStream(file)) {
			props.load(in);
		} catch (IOException ignored) {
			// unreadable file behaves like an empty one
		}
	}

	public synchronized int getApiVersion() {
		return clampVersion(parseInt(props.getProperty(KEY_VERSION), DEFAULT_API_VERSION));
	}

	public synchronized String getServer() {
		return props.getProperty(KEY_SERVER, "");
	}

	public synchronized String getToken() {
		return props.getProperty(KEY_TOKEN, "");
	}

	public synchronized int getRefresh() {
		return parseInt(props.getProperty(KEY_REFRESH), DEFAULT_REFRESH);
	}

	/** The stored mapping for a Burp severity key, exactly as written; "" when unset. */
	public synchronized String getSeverity(String burpKey) {
		return props.getProperty(burpKey, "");
	}

	public synchronized void save(int apiVersion, String server, String token, String refresh) {
		props.setProperty(KEY_VERSION, "" + clampVersion(apiVersion));
		props.setProperty(KEY_SERVER, normaliseServer(server));
		props.setProperty(KEY_TOKEN, token == null ? "" : token.trim());
		props.setProperty(KEY_REFRESH, "" + parseInt(refresh, DEFAULT_REFRESH));
		store();
	}

	public synchronized void saveSeverity(String burpKey, String factionSeverity) {
		if (burpKey == null || burpKey.isEmpty()) return;
		props.setProperty(burpKey, factionSeverity == null ? "" : factionSeverity);
		store();
	}

	/** Trims, drops trailing slashes and a trailing {@code /api/v1} a user may have pasted. */
	public static String normaliseServer(String server) {
		if (server == null) return "";
		String s = server.trim();
		while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
		if (s.endsWith("/api/v1")) s = s.substring(0, s.length() - "/api/v1".length());
		while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
		return s;
	}

	private void store() {
		try {
			Files.createDirectories(file.getParent());
			try (OutputStream out = Files.newOutputStream(file)) {
				props.store(out, "Saved by the Faction Burp extension");
			}
		} catch (IOException e) {
			System.err.println("Faction: failed to save config to " + file + ": " + e);
		}
	}

	private static int clampVersion(int v) {
		return v == 1 ? 1 : DEFAULT_API_VERSION;
	}

	private static int parseInt(String s, int fallback) {
		if (s == null) return fallback;
		try {
			return Integer.parseInt(s.trim());
		} catch (NumberFormatException e) {
			return fallback;
		}
	}
}
