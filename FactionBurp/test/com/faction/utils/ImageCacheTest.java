package com.faction.utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class ImageCacheTest {

	@Test
	void findsPortalImagePathsAcrossFragmentsWithoutDuplicates() {
		List<String> paths = ImageCache.referencedPaths(
				"<p><img src=\"/api/v1/inline-images/aaa\" alt=\"x\"></p>",
				"<img alt='y' src='/api/v1/inline-images/bbb'/> and again <img src=\"/api/v1/inline-images/aaa\">",
				"<img src=\"data:image/png;base64,AAAA\"> <img src=\"https://elsewhere/x.png\">",
				null);
		assertEquals(List.of("/api/v1/inline-images/aaa", "/api/v1/inline-images/bbb"), paths);
	}

	@Test
	void prefetchFetchesEachPathOnceAndServesRepeatsFromCache() {
		AtomicInteger calls = new AtomicInteger();
		ConcurrentHashMap<String, Integer> perPath = new ConcurrentHashMap<>();
		List<String> paths = List.of("/api/v1/inline-images/t1", "/api/v1/inline-images/t2", "/api/v1/inline-images/t3");
		ImageCache.prefetch(paths, p -> { calls.incrementAndGet(); perPath.merge(p, 1, Integer::sum); return p.getBytes(); });
		ImageCache.prefetch(paths, p -> { calls.incrementAndGet(); return null; });
		assertEquals(3, calls.get(), "second prefetch is a no-op");
		assertArrayEquals("/api/v1/inline-images/t2".getBytes(), ImageCache.get("/api/v1/inline-images/t2"));
		assertArrayEquals("/api/v1/inline-images/t3".getBytes(),
				ImageCache.getOrFetch("/api/v1/inline-images/t3", p -> { calls.incrementAndGet(); return null; }));
		assertEquals(3, calls.get());
	}

	@Test
	void failedFetchesAreNotCached() {
		AtomicInteger calls = new AtomicInteger();
		assertNull(ImageCache.getOrFetch("/api/v1/inline-images/missing", p -> { calls.incrementAndGet(); return null; }));
		assertNull(ImageCache.getOrFetch("/api/v1/inline-images/missing", p -> { calls.incrementAndGet(); return null; }));
		assertEquals(2, calls.get(), "retried, not remembered as missing");
	}
}
