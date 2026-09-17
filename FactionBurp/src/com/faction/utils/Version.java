package com.faction.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * The extension's version, as stamped by Maven into
 * {@code faction-version.properties} at build time (resource filtering of
 * {@code ${project.version}}). The release workflow sets the Maven version from
 * the release tag before packaging, so a released jar reports its tag.
 */
public final class Version {

	public static final String UNKNOWN = "dev";
	private static final String RESOURCE = "/faction-version.properties";
	private static volatile String cached;

	private Version() { }

	public static String get() {
		String v = cached;
		if (v == null) {
			cached = v = fromProperties(load());
		}
		return v;
	}

	/** {@link #UNKNOWN} when the value is missing or still the unfiltered placeholder. */
	static String fromProperties(Properties props) {
		if (props == null) return UNKNOWN;
		String v = props.getProperty("version");
		if (v == null) return UNKNOWN;
		v = v.trim();
		if (v.isEmpty() || v.contains("${")) return UNKNOWN;
		return v;
	}

	private static Properties load() {
		try (InputStream in = Version.class.getResourceAsStream(RESOURCE)) {
			if (in == null) return null;
			Properties p = new Properties();
			p.load(in);
			return p;
		} catch (IOException e) {
			return null;
		}
	}
}
