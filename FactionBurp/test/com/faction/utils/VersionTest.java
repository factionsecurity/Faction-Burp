package com.faction.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.Test;

class VersionTest {

	@Test
	void versionComesFromTheFilteredResource() {
		// The resource is filtered by Maven, so the value must be a real version, not the placeholder.
		String v = Version.get();
		assertTrue(v.matches("\\d+\\.\\d+.*"), "expected a Maven version, got: " + v);
	}

	@Test
	void fallsBackWhenTheResourceIsMissingOrUnfiltered() {
		assertEquals(Version.UNKNOWN, Version.fromProperties(null));
		Properties empty = new Properties();
		assertEquals(Version.UNKNOWN, Version.fromProperties(empty));
		Properties unfiltered = new Properties();
		unfiltered.setProperty("version", "${project.version}");
		assertEquals(Version.UNKNOWN, Version.fromProperties(unfiltered));
		Properties ok = new Properties();
		ok.setProperty("version", " 2.1 ");
		assertEquals("2.1", Version.fromProperties(ok));
	}
}
