package com.faction.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FactionConfigTest {

	@TempDir
	Path dir;

	private FactionConfig config() {
		return new FactionConfig(dir.resolve("sub").resolve("faction.properties"));
	}

	@Test
	void defaultsToVersion2WhenFileEmpty() {
		FactionConfig c = config();
		assertEquals(2, c.getApiVersion());
		assertEquals("", c.getServer());
		assertEquals("", c.getToken());
		assertEquals(20, c.getRefresh());
	}

	@Test
	void roundTripsSavedValues() {
		FactionConfig c = config();
		c.save(1, "http://h:8080/api/v1/", "tok", "30");
		FactionConfig again = config();
		assertEquals(1, again.getApiVersion());
		assertEquals("http://h:8080", again.getServer());
		assertEquals("tok", again.getToken());
		assertEquals(30, again.getRefresh());
	}

	@Test
	void badRefreshAndVersionFallBack() {
		FactionConfig c = config();
		c.save(7, "http://h", "t", "abc");
		assertEquals(20, c.getRefresh());
		assertEquals(2, c.getApiVersion());
	}

	@Test
	void severityIsStoredAsGiven() {
		FactionConfig c = config();
		c.saveSeverity(FactionConfig.BURP_SEV_HIGH, "HIGH");
		assertEquals("HIGH", config().getSeverity(FactionConfig.BURP_SEV_HIGH));
		assertEquals("", config().getSeverity(FactionConfig.BURP_SEV_LOW));
	}

	@Test
	void legacyNumericSeverityIsPreserved() throws Exception {
		Path f = dir.resolve("sub").resolve("faction.properties");
		Files.createDirectories(f.getParent());
		Files.writeString(f, "server=http://old\ntoken=abc\nhigh=4\nmedium=3\n");
		FactionConfig c = config();
		assertEquals("4", c.getSeverity("high"));
		assertEquals("3", c.getSeverity("medium"));
		assertEquals(2, c.getApiVersion());
		// Saving other keys must not disturb the legacy values
		c.save(1, "http://old", "abc", "20");
		assertEquals("4", config().getSeverity("high"));
	}

	@Test
	void normaliseServerStripsSlashesAndApiPrefix() {
		assertEquals("https://x.io", FactionConfig.normaliseServer(" https://x.io/api/v1/ "));
		assertEquals("https://x.io/ctx", FactionConfig.normaliseServer("https://x.io/ctx//"));
		assertEquals("", FactionConfig.normaliseServer(null));
	}
}
