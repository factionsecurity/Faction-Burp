package com.faction.utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Session cache of portal-hosted inline images, keyed by their {@code src}
 * path. Swing's HTML renderer loads images synchronously during layout, on the
 * event thread, one after another — so a finding with several screenshots
 * froze Burp for the sum of the round trips. Prefetching them in parallel
 * before the window opens, and serving repeat views from here, removes that.
 */
public final class ImageCache {

	private static final Pattern IMG_SRC = Pattern.compile("(?i)<img\\b[^>]*\\bsrc\\s*=\\s*[\"'](/api/v1/inline-images/[^\"']+)[\"']");
	private static final Map<String, byte[]> CACHE = new ConcurrentHashMap<>();
	private static final int PARALLEL = 4;

	private ImageCache() { }

	/** Portal image paths referenced by any of the given HTML fragments, in order, without duplicates. */
	public static List<String> referencedPaths(String... htmlFragments) {
		Set<String> out = new LinkedHashSet<>();
		for (String html : htmlFragments) {
			if (html == null) continue;
			Matcher m = IMG_SRC.matcher(html);
			while (m.find()) out.add(m.group(1));
		}
		return new ArrayList<>(out);
	}

	/** The cached bytes for a path, or null if it has not been fetched. */
	public static byte[] get(String path) {
		return path == null ? null : CACHE.get(path);
	}

	/** Fetches with {@code fetcher} unless already cached; the result (null included) is not cached when null. */
	public static byte[] getOrFetch(String path, Function<String, byte[]> fetcher) {
		if (path == null) return null;
		byte[] cached = CACHE.get(path);
		if (cached != null) return cached;
		byte[] bytes = fetcher.apply(path);
		if (bytes != null) CACHE.put(path, bytes);
		return bytes;
	}

	/**
	 * Fetches every path not yet cached, several at a time, and returns when
	 * all are done. Failures are skipped: the view shows a missing-image icon.
	 */
	public static void prefetch(Collection<String> paths, Function<String, byte[]> fetcher) {
		List<String> missing = new ArrayList<>();
		for (String p : paths) if (p != null && !CACHE.containsKey(p)) missing.add(p);
		if (missing.isEmpty()) return;
		ExecutorService pool = Executors.newFixedThreadPool(Math.min(PARALLEL, missing.size()), r -> {
			Thread t = new Thread(r, "faction-image-prefetch");
			t.setDaemon(true);
			return t;
		});
		try {
			List<Future<?>> futures = new ArrayList<>();
			for (String p : missing) futures.add(pool.submit(() -> getOrFetch(p, fetcher)));
			for (Future<?> f : futures) {
				try { f.get(); } catch (Exception ignored) { }
			}
		} finally {
			pool.shutdown();
		}
	}
}
